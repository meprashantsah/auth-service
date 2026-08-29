package com.prashant.auth_service.dto;

/**
 * Result of checking an invite link on the public register page.
 *
 * @param valid     true when the token exists, is unused and not yet expired
 * @param roleName  the role the invite grants (populated even when invalid, so
 *                  the UI can say "this invite for ADMIN has expired")
 * @param message   a human-readable reason when {@code valid} is false
 */
public record ValidateInviteResponse(
        boolean valid,
        String roleName,
        String message
) {
}
