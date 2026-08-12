package com.prashant.auth_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.prashant.auth_service.dto.PermissionDto;
import com.prashant.auth_service.dto.RoleDto;
import com.prashant.auth_service.dto.UserDto;
import com.prashant.auth_service.entity.Permission;
import com.prashant.auth_service.entity.Role;
import com.prashant.auth_service.entity.User;
import com.prashant.auth_service.exception.AuthException;
import com.prashant.auth_service.repository.PermissionRepository;
import com.prashant.auth_service.repository.RoleRepository;
import com.prashant.auth_service.repository.UserRepository;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * RBAC Service - Manages roles and permissions, and their assignment to
 * identity users. The user *profile* directory lives in the user-service.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RbacService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    // ==================== ROLE ASSIGNMENT ====================

    @Transactional
    public UserDto assignRoleToUser(UUID userId, String roleName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException("User not found"));
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new AuthException("Role not found: " + roleName));

        user.addRole(role);
        userRepository.save(user);
        log.info("Role {} assigned to user {}", roleName, user.getUsername());
        return mapToUserDto(user);
    }

    @Transactional
    public UserDto removeRoleFromUser(UUID userId, String roleName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException("User not found"));
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new AuthException("Role not found: " + roleName));

        user.removeRole(role);
        userRepository.save(user);
        log.info("Role {} removed from user {}", roleName, user.getUsername());
        return mapToUserDto(user);
    }

    // ==================== ROLE MANAGEMENT ====================

    @Transactional
    public RoleDto createRole(String name, String description, Set<String> permissionNames) {
        if (roleRepository.existsByName(name)) {
            throw new AuthException("Role already exists: " + name);
        }

        Role role = Role.builder()
                .name(name)
                .description(description)
                .build();

        if (permissionNames != null) {
            for (String permName : permissionNames) {
                Permission perm = permissionRepository.findByName(permName)
                        .orElseThrow(() -> new AuthException("Permission not found: " + permName));
                role.getPermissions().add(perm);
            }
        }

        Role saved = roleRepository.save(role);
        log.info("Role created: {}", name);
        return mapToRoleDto(saved);
    }

    @Transactional(readOnly = true)
    public List<RoleDto> getAllRoles() {
        return roleRepository.findAll().stream()
                .map(this::mapToRoleDto)
                .collect(Collectors.toList());
    }

    // ==================== PERMISSION MANAGEMENT ====================

    @Transactional
    public PermissionDto createPermission(String name, String resource, String action, String description) {
        if (permissionRepository.existsByName(name)) {
            throw new AuthException("Permission already exists: " + name);
        }

        Permission perm = Permission.builder()
                .name(name)
                .resource(resource)
                .action(action)
                .description(description)
                .build();

        Permission saved = permissionRepository.save(perm);
        log.info("Permission created: {}", name);
        return mapToPermissionDto(saved);
    }

    @Transactional(readOnly = true)
    public List<PermissionDto> getAllPermissions() {
        return permissionRepository.findAll().stream()
                .map(this::mapToPermissionDto)
                .collect(Collectors.toList());
    }

    // ==================== MAPPERS ====================

    private UserDto mapToUserDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .enabled(user.isEnabled())
                .roles(user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()))
                .permissions(user.getRoles().stream()
                        .flatMap(r -> r.getPermissions().stream())
                        .map(Permission::getName)
                        .collect(Collectors.toSet()))
                .createdAt(user.getCreatedAt())
                .build();
    }

    private RoleDto mapToRoleDto(Role role) {
        return RoleDto.builder()
                .id(role.getId())
                .name(role.getName())
                .description(role.getDescription())
                .permissions(role.getPermissions().stream()
                        .map(Permission::getName)
                        .collect(Collectors.toSet()))
                .build();
    }

    private PermissionDto mapToPermissionDto(Permission perm) {
        return PermissionDto.builder()
                .id(perm.getId())
                .name(perm.getName())
                .resource(perm.getResource())
                .action(perm.getAction())
                .description(perm.getDescription())
                .build();
    }
}