package prashant.auth_service.dto;

import java.time.Instant;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        Instant expiresAt
) {
    public TokenResponse(String accessToken, String refreshToken, Instant expiresAt) {
        this(accessToken, refreshToken, "Bearer", expiresAt);
    }
}
