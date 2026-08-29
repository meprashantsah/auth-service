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
 * - GET    /api/auth/users                  → List all identity users
 * - GET    /api/auth/users/{id}             → Get identity user details
 * - POST   /api/auth/users/{id}/roles       → Assign role to identity user
 * - DELETE /api/auth/users/{id}/roles       → Remove role from identity user
 * - POST   /api/auth/roles                  → Create new role
 * - GET    /api/auth/roles                  → List all roles
 * - POST   /api/auth/permissions            → Create new permission
 * - GET    /api/auth/permissions            → List all permissions
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class RbacController {

    private final RbacService rbacService;

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        return ResponseEntity.ok(rbacService.getAllUsers());
    }

    @GetMapping("/users/{id}")
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<UserDto> getUser(@PathVariable UUID id) {
        return ResponseEntity.ok(rbacService.getUserById(id));
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasAuthority('user:delete')")
    public ResponseEntity<Void> deleteUser(@PathVariable UUID id,
                                           @RequestHeader("X-User-Id") UUID actorId) {
        rbacService.deleteUser(id, actorId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/users/{id}/roles")
    @PreAuthorize("hasAuthority('role:assign')")
    public ResponseEntity<UserDto> assignRole(
            @PathVariable UUID id,
            @RequestBody Map<String, String> request) {
        return ResponseEntity.ok(rbacService.assignRoleToUser(id, request.get("roleName")));
    }

    @DeleteMapping("/users/{id}/roles")
    @PreAuthorize("hasAuthority('role:assign')")
    public ResponseEntity<UserDto> removeRole(
            @PathVariable UUID id,
            @RequestBody Map<String, String> request) {
        return ResponseEntity.ok(rbacService.removeRoleFromUser(id, request.get("roleName")));
    }

    @PostMapping("/roles")
    @PreAuthorize("hasAuthority('role:create')")
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
    @PreAuthorize("hasAuthority('role:read')")
    public ResponseEntity<List<RoleDto>> getAllRoles() {
        return ResponseEntity.ok(rbacService.getAllRoles());
    }

    @DeleteMapping("/roles/{id}")
    @PreAuthorize("hasAuthority('role:delete')")
    public ResponseEntity<Void> deleteRole(@PathVariable UUID id) {
        rbacService.deleteRole(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/permissions")
    @PreAuthorize("hasAuthority('permission:create')")
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
    @PreAuthorize("hasAuthority('permission:read')")
    public ResponseEntity<List<PermissionDto>> getAllPermissions() {
        return ResponseEntity.ok(rbacService.getAllPermissions());
    }

    @DeleteMapping("/permissions/{id}")
    @PreAuthorize("hasAuthority('permission:delete')")
    public ResponseEntity<Void> deletePermission(@PathVariable UUID id) {
        rbacService.deletePermission(id);
        return ResponseEntity.noContent().build();
    }
}