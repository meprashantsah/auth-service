package com.prashant.auth_service.controller;

import com.prashant.auth_service.dto.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import com.prashant.auth_service.dto.*;
import com.prashant.auth_service.security.UserPrincipal;
import com.prashant.auth_service.service.AuthService;
import com.prashant.auth_service.service.JwtService;

/**
 * Auth Controller - Public authentication endpoints.
 *
 * Endpoints:
 * - POST /api/auth/register    → Create new user account
 * - POST /api/auth/login       → Authenticate and get tokens
 * - POST /api/auth/refresh     → Get new access token using refresh token
 * - POST /api/auth/logout      → Revoke tokens and logout
 * - POST /api/auth/validate    → Validate token (internal/Gateway use)
 * - GET  /api/auth/me          → Get current user details
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody(required = false) RefreshTokenRequest refreshTokenRequest) {

        String accessToken = authHeader.substring(7);
        String refreshToken = refreshTokenRequest != null ? refreshTokenRequest.getRefreshToken() : null;

        authService.logout(accessToken, refreshToken);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/validate")
    public ResponseEntity<TokenValidationResponse> validateToken(
            @Valid @RequestBody TokenValidationRequest request) {
        return ResponseEntity.ok(jwtService.validateToken(request));
    }

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserDto> getCurrentUser(
            @AuthenticationPrincipal UserPrincipal principal) {
        return ResponseEntity.ok(authService.getCurrentUser(principal.getUsername()));
    }
}
