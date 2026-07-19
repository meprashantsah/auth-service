package prashant.auth_service.controller;

import prashant.auth_service.dto.*;
import prashant.auth_service.service.AuthService;
import prashant.common.dto.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserDto>> register(@Valid @RequestBody RegisterRequest request) {
        UserDto user = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(user, "User registered successfully"));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest request,
                                                            HttpServletRequest httpRequest) {
        String ipAddress = httpRequest.getHeader("X-Forwarded-For");
        if (ipAddress == null) {
            ipAddress = httpRequest.getRemoteAddr();
        }
        TokenResponse tokens = authService.login(request, ipAddress);
        return ResponseEntity.ok(ApiResponse.success(tokens, "Login successful"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<TokenResponse>> refresh(@Valid @RequestBody RefreshRequest request) {
        TokenResponse tokens = authService.refresh(request);
        return ResponseEntity.ok(ApiResponse.success(tokens, "Token refreshed successfully"));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@AuthenticationPrincipal Jwt jwt,
                                                    @Valid @RequestBody LogoutRequest request) {
        authService.logout(jwt.getTokenValue(), request.refreshToken());
        return ResponseEntity.ok(ApiResponse.success(null, "Logout successful"));
    }

    @PostMapping("/logout-all")
    public ResponseEntity<ApiResponse<Void>> logoutAll(@AuthenticationPrincipal Jwt jwt) {
        UUID userId = UUID.fromString(Objects.requireNonNull(jwt.getSubject()));
        authService.logoutAll(userId);
        return ResponseEntity.ok(ApiResponse.success(null, "All sessions terminated"));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<MeResponse>> getCurrentUser(@AuthenticationPrincipal Jwt jwt) {
        MeResponse user = authService.getCurrentUser(jwt.getTokenValue());
        return ResponseEntity.ok(ApiResponse.success(user, "Current user retrieved"));
    }
}
