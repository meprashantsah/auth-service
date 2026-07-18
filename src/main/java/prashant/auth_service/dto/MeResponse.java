package prashant.auth_service.dto;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record MeResponse(
        UUID id,
        String phoneNumber,
        String username,
        String displayName,
        String email,
        boolean emailVerified,
        Set<String> roles,
        Instant createdAt
) {}