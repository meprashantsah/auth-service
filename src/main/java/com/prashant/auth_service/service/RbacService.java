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
import org.springframework.data.domain.Sort;

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

    // ==================== IDENTITY USER DIRECTORY ====================

    @Transactional(readOnly = true)
    public List<UserDto> getAllUsers() {
        return userRepository.findAll(Sort.by(Sort.Direction.DESC, "createdAt")).stream()
                .map(this::mapToUserDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public UserDto getUserById(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException("User not found"));
        return mapToUserDto(user);
    }

    @Transactional
    public void deleteUser(UUID userId, UUID actorId) {
        if (userId.equals(actorId)) {
            throw new AuthException("You cannot delete your own account");
        }
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException("User not found"));

        boolean isSuperAdmin = user.getRoles().stream()
                .anyMatch(r -> r.getName().equalsIgnoreCase("SUPERADMIN"));
        if (isSuperAdmin && userRepository.countByRoles_Name("SUPERADMIN") <= 1) {
            throw new AuthException("Cannot delete the last SUPERADMIN");
        }

        user.getRoles().clear();
        userRepository.delete(user);
        log.info("User deleted: {} ({})", user.getUsername(), userId);
    }

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

    @Transactional
    public void deleteRole(UUID roleId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new AuthException("Role not found"));
        if (!role.getUsers().isEmpty()) {
            throw new AuthException("Role is still assigned to users and cannot be deleted");
        }
        role.getUsers().clear();
        role.getPermissions().clear();
        roleRepository.delete(role);
        log.info("Role deleted: {}", role.getName());
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

    @Transactional
    public void deletePermission(UUID permissionId) {
        Permission perm = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new AuthException("Permission not found"));
        if (roleRepository.existsByPermissions_Id(permissionId)) {
            throw new AuthException("Permission is assigned to a role and cannot be deleted");
        }
        permissionRepository.delete(perm);
        log.info("Permission deleted: {}", perm.getName());
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