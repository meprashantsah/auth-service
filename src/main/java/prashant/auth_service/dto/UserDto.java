package prashant.auth_service.dto;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record UserDto(
        UUID id,
        String phoneNumber,
        String username,
        String displayName,
        String email,
        boolean emailVerified,
        boolean enabled,
        Set<String> roles,
        Instant createdAt
) {}
