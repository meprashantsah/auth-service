package com.prashant.auth_service.controller;

import com.prashant.auth_service.dto.InviteDto;
import com.prashant.auth_service.dto.ValidateInviteRequest;
import com.prashant.auth_service.dto.ValidateInviteResponse;
import com.prashant.auth_service.service.InviteService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Workspace invite API.
 *
 * Admin endpoints:
 * - POST   /api/auth/invites            → create an invite for a chosen role
 * - GET    /api/auth/invites            → list invites with their state
 * - DELETE /api/auth/invites/{id}       → revoke an invite
 *
 * Public endpoint:
 * - POST /api/auth/invites/validate     → confirm a link before registering
 */
@RestController
@RequestMapping("/api/auth/invites")
@RequiredArgsConstructor
public class InviteController {

    private final InviteService inviteService;

    @PostMapping("/validate")
    public ResponseEntity<ValidateInviteResponse> validate(
            @Valid @RequestBody ValidateInviteRequest request) {
        return ResponseEntity.ok(inviteService.validate(request.token()));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('role:assign')")
    public ResponseEntity<InviteDto> create(
            @RequestHeader("X-User-Id") UUID actorId,
            @RequestBody Map<String, Object> request) {
        String roleName = request.get("roleName") instanceof String s ? s : null;
        Integer validDays = request.get("validDays") instanceof Number n ? n.intValue() : null;
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(inviteService.create(actorId, roleName, validDays));
    }

    @GetMapping
    @PreAuthorize("hasAuthority('role:read')")
    public ResponseEntity<List<InviteDto>> list() {
        return ResponseEntity.ok(inviteService.listAll());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('role:assign')")
    public ResponseEntity<Void> revoke(@PathVariable UUID id) {
        inviteService.revoke(id);
        return ResponseEntity.noContent().build();
    }
}
