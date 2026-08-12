package com.prashant.auth_service.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import com.prashant.auth_service.dto.PermissionDto;
import com.prashant.auth_service.dto.RoleDto;
import com.prashant.auth_service.dto.UserDto;
import com.prashant.auth_service.service.RbacService;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * RBAC Controller - Role & permission management (Admin only).
 *
 * Endpoints:
 * - POST   /api/auth/users/{id}/roles   → Assign role to identity user
 * - DELETE /api/auth/users/{id}/roles   → Remove role from identity user
 * - POST   /api/auth/roles              → Create new role
 * - GET    /api/auth/roles              → List all roles
 * - POST   /api/auth/permissions        → Create new permission
 * - GET    /api/auth/permissions        → List all permissions
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class RbacController {

    private final RbacService rbacService;

    @PostMapping("/users/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDto> assignRole(
            @PathVariable UUID id,
            @RequestBody Map<String, String> request) {
        return ResponseEntity.ok(rbacService.assignRoleToUser(id, request.get("roleName")));
    }

    @DeleteMapping("/users/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDto> removeRole(
            @PathVariable UUID id,
            @RequestBody Map<String, String> request) {
        return ResponseEntity.ok(rbacService.removeRoleFromUser(id, request.get("roleName")));
    }

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
                .body(rbacService.createRole(name, description, permissions));
    }

    @GetMapping("/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<RoleDto>> getAllRoles() {
        return ResponseEntity.ok(rbacService.getAllRoles());
    }

    @PostMapping("/permissions")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PermissionDto> createPermission(@RequestBody Map<String, String> request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(rbacService.createPermission(
                        request.get("name"),
                        request.get("resource"),
                        request.get("action"),
                        request.get("description")
                ));
    }

    @GetMapping("/permissions")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PermissionDto>> getAllPermissions() {
        return ResponseEntity.ok(rbacService.getAllPermissions());
    }
}