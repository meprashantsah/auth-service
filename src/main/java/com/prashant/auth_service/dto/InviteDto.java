package com.prashant.auth_service.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public record InviteDto(
        UUID id,
        String token,
        String roleName,
        LocalDateTime createdAt,
        LocalDateTime expiresAt,
        LocalDateTime usedAt
) {

    public boolean active() {
        return usedAt == null && expiresAt != null && expiresAt.isAfter(LocalDateTime.now());
    }
}
