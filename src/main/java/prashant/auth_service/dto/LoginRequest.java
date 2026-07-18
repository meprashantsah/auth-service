package prashant.auth_service.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "Phone number or username is required")
        String phoneNumberOrUsername,

        @NotBlank(message = "Password is required")
        String password,

        String deviceInfo
) {}
