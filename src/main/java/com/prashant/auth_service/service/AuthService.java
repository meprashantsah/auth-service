package com.prashant.auth_service.service;

import com.prashant.auth_service.client.UserServiceClient;
import com.prashant.auth_service.dto.*;
import com.prashant.auth_service.entity.Permission;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.prashant.auth_service.dto.*;
import com.prashant.auth_service.entity.Role;
import com.prashant.auth_service.entity.User;
import com.prashant.auth_service.exception.AuthException;
import com.prashant.auth_service.repository.RoleRepository;
import com.prashant.auth_service.repository.UserRepository;
import com.prashant.auth_service.security.JwtTokenProvider;
import com.prashant.auth_service.security.UserPrincipal;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.stream.Collectors;

/**
 * Auth Service - Core authentication business logic.
 *
 * - Login with username/password
 * - User registration with role assignment
 * - Token refresh with rotation
 * - Logout with token revocation
 * - Account lockout after failed attempts
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final PasswordEncoder passwordEncoder;
    private final UserServiceClient userServiceClient;

    @Value("${security.max-login-attempts:5}")
    private int maxLoginAttempts;

    @Value("${security.lockout-duration:900}")
    private long lockoutDurationSeconds;

    @Transactional
    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new AuthException("Invalid username or password"));

        // Check if account is locked
        if (!user.isAccountNonLocked()) {
            if (user.getLockTime() != null &&
                user.getLockTime().plusSeconds(lockoutDurationSeconds).isAfter(LocalDateTime.now())) {
                throw new LockedException("Account is locked. Please try again later.");
            } else {
                // Unlock account after lockout duration
                user.setAccountNonLocked(true);
                user.setFailedAttempt(0);
                user.setLockTime(null);
                userRepository.save(user);
            }
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Reset failed attempts on successful login
            user.setFailedAttempt(0);
            userRepository.save(user);

            String accessToken = jwtTokenProvider.generateAccessToken(authentication);
            String refreshToken = jwtTokenProvider.generateRefreshToken(authentication);

            // Store refresh token hash in database
            refreshTokenService.createRefreshToken(user, refreshToken);

            log.info("User logged in successfully: {}", request.getUsername());

            return TokenResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(jwtTokenProvider.getAccessTokenExpirySeconds())
                    .refreshExpiresIn(jwtTokenProvider.getRefreshTokenExpirySeconds())
                    .build();

        } catch (BadCredentialsException e) {
            handleFailedLogin(user);
            throw new AuthException("Invalid username or password");
        }
    }

    @Transactional
    public UserDto register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new AuthException("Username already taken");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AuthException("Email already registered");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .enabled(true)
                .accountNonLocked(true)
                .roles(new HashSet<>())
                .build();

        // Assign default ROLE_USER
        Role userRole = roleRepository.findByName("USER")
                .orElseGet(() -> roleRepository.save(Role.builder().name("USER").description("Default user role").build()));
        user.addRole(userRole);

        // Assign additional roles from request
        if (request.getRoles() != null) {
            for (String roleName : request.getRoles()) {
                Role role = roleRepository.findByName(roleName)
                        .orElseThrow(() -> new AuthException("Role not found: " + roleName));
                user.addRole(role);
            }
        }

        User saved = userRepository.save(user);

        // Create the user profile in the user-service (same logical user id).
        // Throwing here rolls back the identity creation so registration is atomic.
        userServiceClient.createUserProfile(
                saved.getId(), saved.getUsername(), saved.getUsername(), saved.getEmail());

        log.info("User registered successfully: {}", saved.getUsername());

        return mapToUserDto(saved);
    }

    @Transactional
    public TokenResponse refreshToken(RefreshTokenRequest request) {
        // Validate the refresh token JWT structure
        Claims claims = jwtTokenProvider.validateToken(request.getRefreshToken());

        if (!"REFRESH".equals(claims.get("type", String.class))) {
            throw new AuthException("Invalid token type");
        }

        User user = userRepository.findById(java.util.UUID.fromString(claims.getSubject()))
                .orElseThrow(() -> new AuthException("User not found"));

        // Validate against database (hash comparison)
        if (!refreshTokenService.validateRefreshToken(request.getRefreshToken(), user)) {
            throw new AuthException("Invalid or expired refresh token");
        }

        // Revoke old refresh token (rotation)
        refreshTokenService.revokeRefreshToken(request.getRefreshToken(), user);

        // Generate new tokens
        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        UserPrincipal.create(user), null, UserPrincipal.create(user).getAuthorities());

        String newAccessToken = jwtTokenProvider.generateAccessToken(authentication);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(authentication);

        // Store new refresh token
        refreshTokenService.createRefreshToken(user, newRefreshToken);

        log.info("Token refreshed for user: {}", user.getUsername());

        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getAccessTokenExpirySeconds())
                .build();
    }

    @Transactional
    public void logout(String accessToken, String refreshToken) {
        // Blacklist access token
        String accessJti = jwtTokenProvider.getTokenId(accessToken);
        tokenBlacklistService.blacklistToken(accessJti, jwtTokenProvider.getExpiryDate(accessToken));

        // Revoke refresh token
        if (refreshToken != null) {
            Claims claims = jwtTokenProvider.validateToken(refreshToken);
            User user = userRepository.findById(java.util.UUID.fromString(claims.getSubject()))
                    .orElseThrow(() -> new AuthException("User not found"));
            refreshTokenService.revokeRefreshToken(refreshToken, user);
        }

        log.info("User logged out successfully");
    }

    @Transactional(readOnly = true)
    public UserDto getCurrentUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new AuthException("User not found"));
        return mapToUserDto(user);
    }

    private void handleFailedLogin(User user) {
        int attempts = user.getFailedAttempt() + 1;
        user.setFailedAttempt(attempts);

        if (attempts >= maxLoginAttempts) {
            user.setAccountNonLocked(false);
            user.setLockTime(LocalDateTime.now());
            log.warn("Account locked for user: {} after {} failed attempts", user.getUsername(), attempts);
        }

        userRepository.save(user);
    }

    private UserDto mapToUserDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .enabled(user.isEnabled())
                .roles(user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()))
                .permissions(user.getRoles().stream()
                        .flatMap(r -> r.getPermissions().stream())
                        .map(Permission::getName)
                        .collect(Collectors.toSet()))
                .createdAt(user.getCreatedAt())
                .build();
    }
}
