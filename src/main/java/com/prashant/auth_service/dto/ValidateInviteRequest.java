package com.prashant.auth_service.dto;

import jakarta.validation.constraints.NotBlank;

public record ValidateInviteRequest(
        @NotBlank(message = "Invite token is required")
        String token
) {
}
