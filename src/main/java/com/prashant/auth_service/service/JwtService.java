package com.prashant.auth_service.service;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import com.prashant.auth_service.dto.TokenValidationRequest;
import com.prashant.auth_service.dto.TokenValidationResponse;
import com.prashant.auth_service.security.JwtTokenProvider;

import java.util.List;

/**
 * JWT Service - Handles token validation and introspection operations.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtTokenProvider jwtTokenProvider;
    private final TokenBlacklistService tokenBlacklistService;

    public TokenValidationResponse validateToken(TokenValidationRequest request) {
        try {
            Claims claims = jwtTokenProvider.validateToken(request.getToken());

            // Check blacklist
            String jti = claims.getId();
            if (tokenBlacklistService.isBlacklisted(jti)) {
                return TokenValidationResponse.builder()
                        .valid(false)
                        .message("Token has been revoked")
                        .build();
            }

            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);

            return TokenValidationResponse.builder()
                    .valid(true)
                    .userId(claims.getSubject())
                    .username(claims.get("username", String.class))
                    .roles(roles)
                    .expiry(claims.getExpiration().getTime())
                    .message("Token is valid")
                    .build();

        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return TokenValidationResponse.builder()
                    .valid(false)
                    .message(e.getMessage())
                    .build();
        }
    }
}
