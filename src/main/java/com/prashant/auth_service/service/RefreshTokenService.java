package com.prashant.auth_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.prashant.auth_service.entity.RefreshToken;
import com.prashant.auth_service.entity.User;
import com.prashant.auth_service.repository.RefreshTokenRepository;

import java.time.LocalDateTime;

/**
 * Refresh Token Service - Manages refresh token lifecycle.
 *
 * - Creates and stores refresh tokens (hashed for security)
 * - Validates refresh tokens against database
 * - Revokes tokens on logout
 * - Cleans up expired tokens periodically
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.refresh-token-expiry:604800}")
    private long refreshTokenExpirySeconds;

    @Transactional
    public RefreshToken createRefreshToken(User user, String rawToken) {
        // Hash the token before storing (security best practice)
        String tokenHash = passwordEncoder.encode(rawToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .tokenHash(tokenHash)
                .user(user)
                .expiryDate(LocalDateTime.now().plusSeconds(refreshTokenExpirySeconds))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional(readOnly = true)
    public boolean validateRefreshToken(String rawToken, User user) {
        // Find all non-revoked tokens for user and check hash match
        return refreshTokenRepository.findAll().stream()
                .filter(rt -> rt.getUser().getId().equals(user.getId()))
                .filter(rt -> !rt.isRevoked())
                .filter(rt -> rt.getExpiryDate().isAfter(LocalDateTime.now()))
                .anyMatch(rt -> passwordEncoder.matches(rawToken, rt.getTokenHash()));
    }

    @Transactional
    public void revokeRefreshToken(String rawToken, User user) {
        refreshTokenRepository.findAll().stream()
                .filter(rt -> rt.getUser().getId().equals(user.getId()))
                .filter(rt -> passwordEncoder.matches(rawToken, rt.getTokenHash()))
                .forEach(rt -> {
                    rt.setRevoked(true);
                    refreshTokenRepository.save(rt);
                });
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllByUser(user);
        log.info("All refresh tokens revoked for user: {}", user.getUsername());
    }

    @Scheduled(cron = "0 0 2 * * ?") // Daily at 2 AM
    @Transactional
    public void cleanupExpiredTokens() {
        int deleted = refreshTokenRepository.deleteAllExpiredBefore(LocalDateTime.now());
        log.info("Cleaned up {} expired refresh tokens", deleted);
    }
}
