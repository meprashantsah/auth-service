package prashant.auth_service.controller;

import prashant.auth_service.dto.*;
import prashant.auth_service.service.AuthService;
import prashant.common.dto.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/internal")
@RequiredArgsConstructor
public class InternalController {

    private final AuthService authService;

    @PostMapping("/auth/validate")
    public ResponseEntity<ApiResponse<UserDto>> validateToken(@Valid @RequestBody ValidateTokenRequest request) {
        UserDto user = authService.validateToken(request.token());
        return ResponseEntity.ok(ApiResponse.success(user, "Token valid"));
    }

    @GetMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<UserDto>> getUserById(@PathVariable UUID userId) {
        UserDto user = authService.getUserById(userId);
        return ResponseEntity.ok(ApiResponse.success(user, "User found"));
    }
}
