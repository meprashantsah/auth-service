package com.prashant.auth_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.prashant.auth_service.entity.RefreshToken;
import com.prashant.auth_service.entity.User;
import com.prashant.auth_service.repository.RefreshTokenRepository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;

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

    @Value("${jwt.refresh-token-expiry:604800}")
    private long refreshTokenExpirySeconds;

    @Transactional
    public RefreshToken createRefreshToken(User user, String rawToken) {
        String tokenHash = hashToken(rawToken);

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
        String tokenHash = hashToken(rawToken);
        return refreshTokenRepository.findAll().stream()
                .filter(rt -> rt.getUser().getId().equals(user.getId()))
                .filter(rt -> !rt.isRevoked())
                .filter(rt -> rt.getExpiryDate().isAfter(LocalDateTime.now()))
                .anyMatch(rt -> tokenHash.contentEquals(rt.getTokenHash()));
    }

    @Transactional
    public void revokeRefreshToken(String rawToken, User user) {
        String tokenHash = hashToken(rawToken);
        refreshTokenRepository.findAll().stream()
                .filter(rt -> rt.getUser().getId().equals(user.getId()))
                .filter(rt -> tokenHash.contentEquals(rt.getTokenHash()))
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

    private String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    @Scheduled(cron = "0 0 2 * * ?") // Daily at 2 AM
    @Transactional
    public void cleanupExpiredTokens() {
        int deleted = refreshTokenRepository.deleteAllExpiredBefore(LocalDateTime.now());
        log.info("Cleaned up {} expired refresh tokens", deleted);
    }
}
