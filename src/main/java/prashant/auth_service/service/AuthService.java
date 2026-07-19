package prashant.auth_service.service;

import prashant.auth_service.dto.*;
import prashant.auth_service.entity.RefreshToken;
import prashant.auth_service.entity.Role;
import prashant.auth_service.entity.User;
import prashant.auth_service.repository.RefreshTokenRepository;
import prashant.auth_service.repository.RoleRepository;
import prashant.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";
    private static final String ROLE_USER = "ROLE_USER";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final StringRedisTemplate redisTemplate;

    public UserDto register(RegisterRequest request) {
        if (userRepository.existsByPhoneNumber(request.phoneNumber())) {
            throw new IllegalArgumentException("Phone number already registered");
        }
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Username already taken");
        }

        Role userRole = roleRepository.findByName(ROLE_USER)
                .orElseThrow(() -> new IllegalStateException("Default role not found"));

        User user = User.builder()
                .phoneNumber(request.phoneNumber())
                .username(request.username())
                .passwordHash(passwordEncoder.encode(request.password()))
                .displayName(request.displayName())
                .build();
        user.getRoles().add(userRole);

        User saved = userRepository.save(user);
        return toUserDto(saved);
    }

    public TokenResponse login(LoginRequest request, String ipAddress) {
        User user = userRepository.findByPhoneNumberOrUsername(request.phoneNumberOrUsername())
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        if (!user.isEnabled()) {
            throw new IllegalArgumentException("Account is disabled");
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        Set<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());
        String accessToken = jwtService.generateAccessToken(user.getId(), user.getUsername(), roles);
        String refreshToken = jwtService.generateRefreshToken();

        String refreshTokenHash = hashToken(refreshToken);
        Instant expiresAt = Instant.now().plus(7, ChronoUnit.DAYS);

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .userId(user.getId())
                .tokenHash(refreshTokenHash)
                .expiresAt(expiresAt)
                .deviceInfo(request.deviceInfo())
                .ipAddress(ipAddress)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);

        return new TokenResponse(accessToken, refreshToken, jwtService.getExpiration(accessToken));
    }

    public TokenResponse refresh(RefreshRequest request) {
        String tokenHash = hashToken(request.refreshToken());
        RefreshToken refreshTokenEntity = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));

        if (refreshTokenEntity.isRevoked()) {
            throw new IllegalArgumentException("Refresh token has been revoked");
        }

        if (refreshTokenEntity.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalArgumentException("Refresh token has expired");
        }

        refreshTokenRepository.revokeByTokenHash(tokenHash);

        User user = userRepository.findById(refreshTokenEntity.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.isEnabled()) {
            throw new IllegalArgumentException("Account is disabled");
        }

        Set<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());
        String newAccessToken = jwtService.generateAccessToken(user.getId(), user.getUsername(), roles);
        String newRefreshToken = jwtService.generateRefreshToken();

        String newRefreshTokenHash = hashToken(newRefreshToken);
        Instant newExpiresAt = Instant.now().plus(7, ChronoUnit.DAYS);

        RefreshToken newRefreshTokenEntity = RefreshToken.builder()
                .userId(user.getId())
                .tokenHash(newRefreshTokenHash)
                .expiresAt(newExpiresAt)
                .deviceInfo(refreshTokenEntity.getDeviceInfo())
                .ipAddress(refreshTokenEntity.getIpAddress())
                .build();
        refreshTokenRepository.save(newRefreshTokenEntity);

        return new TokenResponse(newAccessToken, newRefreshToken, jwtService.getExpiration(newAccessToken));
    }

    public void logout(String accessToken, String refreshToken) {
        long remainingTtl = jwtService.getRemainingTtlSeconds(accessToken);
        if (remainingTtl > 0) {
            String jti = jwtService.parseClaims(accessToken).getId();
            redisTemplate.opsForValue().set(
                    BLACKLIST_PREFIX + jti,
                    "revoked",
                    java.time.Duration.ofSeconds(remainingTtl)
            );
        }

        String tokenHash = hashToken(refreshToken);
        refreshTokenRepository.revokeByTokenHash(tokenHash);
    }

    public void logoutAll(UUID userId) {
        refreshTokenRepository.revokeAllByUserId(userId);
    }

    public MeResponse getCurrentUser(String token) {
        UUID userId = jwtService.getUserIdFromToken(token);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return new MeResponse(
                user.getId(),
                user.getPhoneNumber(),
                user.getUsername(),
                user.getDisplayName(),
                user.getEmail(),
                user.isEmailVerified(),
                user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()),
                user.getCreatedAt()
        );
    }

    public UserDto validateToken(String token) {
        if (!jwtService.validateToken(token)) {
            throw new IllegalArgumentException("Invalid token");
        }

        String jti = jwtService.parseClaims(token).getId();
        if (Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + jti))) {
            throw new IllegalArgumentException("Token has been revoked");
        }

        UUID userId = jwtService.getUserIdFromToken(token);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return toUserDto(user);
    }

    public UserDto getUserById(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return toUserDto(user);
    }

    public boolean isTokenBlacklisted(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + jti));
    }

    private UserDto toUserDto(User user) {
        return new UserDto(
                user.getId(),
                user.getPhoneNumber(),
                user.getUsername(),
                user.getDisplayName(),
                user.getEmail(),
                user.isEmailVerified(),
                user.isEnabled(),
                user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()),
                user.getCreatedAt()
        );
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }
}
