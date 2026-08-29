package com.prashant.auth_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Token Blacklist Service using Redis.
 *
 * Stores revoked access token JTIs (JWT IDs) with TTL equal to token's remaining lifetime.
 * This allows the Gateway and Auth Service to reject logged-out tokens until they naturally expire.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private static final String BLACKLIST_PREFIX = "blacklist:";

    private final RedisTemplate<String, String> redisTemplate;

    /**
     * Blacklists a token by its JTI with TTL equal to token's remaining lifetime.
     */
    public void blacklistToken(String jti, Date expiryDate) {
        long ttlSeconds = Duration.between(Instant.now(), expiryDate.toInstant()).getSeconds();
        if (ttlSeconds > 0) {
            String key = BLACKLIST_PREFIX + jti;
            redisTemplate.opsForValue().set(key, "revoked", ttlSeconds, TimeUnit.SECONDS);
            log.info("Token blacklisted: {}, TTL: {}s", jti, ttlSeconds);
        }
    }

    /**
     * Checks if a token JTI is blacklisted.
     */
    public boolean isBlacklisted(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + jti));
    }
}
