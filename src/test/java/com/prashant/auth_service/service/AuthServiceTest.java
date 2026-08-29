package com.prashant.auth_service.service;

import com.prashant.auth_service.client.UserServiceClient;
import com.prashant.auth_service.dto.RegisterRequest;
import com.prashant.auth_service.entity.Role;
import com.prashant.auth_service.entity.User;
import com.prashant.auth_service.exception.AuthException;
import com.prashant.auth_service.repository.RoleRepository;
import com.prashant.auth_service.repository.UserRepository;
import com.prashant.auth_service.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtTokenProvider jwtTokenProvider;
    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private TokenBlacklistService tokenBlacklistService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private UserServiceClient userServiceClient;
    @Mock
    private InviteService inviteService;

    private AuthService authService;

    private UUID userId;

    @BeforeEach
    void setUp() {
        authService = new AuthService(
                authenticationManager, jwtTokenProvider, userRepository, roleRepository,
                refreshTokenService, tokenBlacklistService, passwordEncoder, userServiceClient,
                inviteService);
        userId = UUID.randomUUID();
    }

    private RegisterRequest registerRequest(String username, String email) {
        RegisterRequest request = new RegisterRequest();
        request.setUsername(username);
        request.setEmail(email);
        request.setPassword("password123");
        return request;
    }

    @Test
    void register_createsIdentityAndProfileInUserService() {
        when(userRepository.existsByUsername("alice")).thenReturn(false);
        when(userRepository.existsByEmail("alice@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("$2a$hash");
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(Role.builder().name("USER").permissions(new HashSet<>()).build()));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(userId);
            return u;
        });

        authService.register(registerRequest("alice", "alice@example.com"));

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getUsername()).isEqualTo("alice");

        verify(userServiceClient).createUserProfile(userId, "alice", "alice", "alice@example.com");
    }

    @Test
    void register_failsWhenProfileCreationFails() {
        when(userRepository.existsByUsername("alice")).thenReturn(false);
        when(userRepository.existsByEmail("alice@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("$2a$hash");
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(Role.builder().name("USER").permissions(new HashSet<>()).build()));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(userId);
            return u;
        });
        org.mockito.Mockito.doThrow(new AuthException("Registration failed"))
                .when(userServiceClient).createUserProfile(any(), any(), any(), any());

        assertThatThrownBy(() -> authService.register(registerRequest("alice", "alice@example.com")))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Registration failed");
    }

    @Test
    void register_rejectsDuplicateUsername() {
        when(userRepository.existsByUsername("taken")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(
                registerRequest("taken", "x@example.com")))
                .isInstanceOf(AuthException.class);

        verify(userServiceClient, never()).createUserProfile(any(), any(), any(), any());
    }

    @Test
    void register_redeemsInviteAndGrantsItsRole() {
        when(userRepository.existsByUsername("bob")).thenReturn(false);
        when(userRepository.existsByEmail("bob@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("$2a$hash");
        when(roleRepository.findByName("USER"))
                .thenReturn(Optional.of(Role.builder().name("USER").permissions(new HashSet<>()).build()));
        when(inviteService.redeem("tok-1")).thenReturn("ADMIN");
        when(roleRepository.findByName("ADMIN"))
                .thenReturn(Optional.of(Role.builder().name("ADMIN").permissions(new HashSet<>()).build()));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(userId);
            return u;
        });

        RegisterRequest request = registerRequest("bob", "bob@example.com");
        request.setInviteToken("tok-1");
        authService.register(request);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getRoles())
                .extracting(Role::getName)
                .containsExactlyInAnyOrder("USER", "ADMIN");
        verify(userServiceClient).createUserProfile(userId, "bob", "bob", "bob@example.com");
    }

    @Test
    void register_rejectsInvalidInvite() {
        when(userRepository.existsByUsername("bob")).thenReturn(false);
        when(userRepository.existsByEmail("bob@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("$2a$hash");
        when(roleRepository.findByName("USER"))
                .thenReturn(Optional.of(Role.builder().name("USER").permissions(new HashSet<>()).build()));
        when(inviteService.redeem("tok-1"))
                .thenThrow(new AuthException("This invite has expired"));

        RegisterRequest request = registerRequest("bob", "bob@example.com");
        request.setInviteToken("tok-1");

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("expired");
        verify(userServiceClient, never()).createUserProfile(any(), any(), any(), any());
    }
}
