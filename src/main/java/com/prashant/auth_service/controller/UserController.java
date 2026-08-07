package com.prashant.auth_service.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import com.prashant.auth_service.dto.PermissionDto;
import com.prashant.auth_service.dto.RoleDto;
import com.prashant.auth_service.dto.UserDto;
import com.prashant.auth_service.service.UserService;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * User Controller - RBAC management endpoints (Admin only).
 *
 * Endpoints:
 * - GET    /api/auth/users              → List all users
 * - GET    /api/auth/users/{id}         → Get user by ID
 * - POST   /api/auth/users/{id}/roles   → Assign role to user
 * - DELETE /api/auth/users/{id}/roles   → Remove role from user
 * - POST   /api/auth/roles              → Create new role
 * - GET    /api/auth/roles              → List all roles
 * - POST   /api/auth/permissions        → Create new permission
 * - GET    /api/auth/permissions        → List all permissions
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    // ==================== USER MANAGEMENT ====================

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isCurrentUser(#id, authentication)")
    public ResponseEntity<UserDto> getUserById(@PathVariable UUID id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }

    @PostMapping("/users/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDto> assignRole(
            @PathVariable UUID id,
            @RequestBody Map<String, String> request) {
        return ResponseEntity.ok(userService.assignRoleToUser(id, request.get("roleName")));
    }

    @DeleteMapping("/users/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDto> removeRole(
            @PathVariable UUID id,
            @RequestBody Map<String, String> request) {
        return ResponseEntity.ok(userService.removeRoleFromUser(id, request.get("roleName")));
    }

    // ==================== ROLE MANAGEMENT ====================

    @PostMapping("/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<RoleDto> createRole(@RequestBody Map<String, Object> request) {
        String name = (String) request.get("name");
        String description = (String) request.get("description");
        @SuppressWarnings("unchecked")
        Set<String> permissions = request.containsKey("permissions")
                ? Set.copyOf((List<String>) request.get("permissions"))
                : null;

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(userService.createRole(name, description, permissions));
    }

    @GetMapping("/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<RoleDto>> getAllRoles() {
        return ResponseEntity.ok(userService.getAllRoles());
    }

    // ==================== PERMISSION MANAGEMENT ====================

    @PostMapping("/permissions")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PermissionDto> createPermission(@RequestBody Map<String, String> request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(userService.createPermission(
                        request.get("name"),
                        request.get("resource"),
                        request.get("action"),
                        request.get("description")
                ));
    }

    @GetMapping("/permissions")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PermissionDto>> getAllPermissions() {
        return ResponseEntity.ok(userService.getAllPermissions());
    }
}
