package com.prashant.auth_service.service;

import com.prashant.auth_service.dto.InviteDto;
import com.prashant.auth_service.dto.ValidateInviteResponse;
import com.prashant.auth_service.entity.Invite;
import com.prashant.auth_service.exception.AuthException;
import com.prashant.auth_service.repository.InviteRepository;
import com.prashant.auth_service.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Workspace invite lifecycle: create (with a fixed role), validate, redeem on
 * registration, list and revoke. Invites are the only way public registration
 * can grant an elevated role — the client never supplies the role itself.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class InviteService {

    private final InviteRepository inviteRepository;
    private final RoleRepository roleRepository;

    @Value("${app.invite.default-valid-days:7}")
    private int defaultValidDays;

    @Transactional
    public InviteDto create(UUID createdBy, String roleName, Integer validDays) {
        String role = roleName == null || roleName.isBlank() ? "USER" : roleName.trim();
        if (!roleRepository.existsByName(role)) {
            throw new AuthException("Role not found: " + role);
        }
        if (createdBy == null) {
            throw new AuthException("Missing actor id");
        }

        Invite invite = Invite.builder()
                .id(UUID.randomUUID())
                .token(generateToken())
                .roleName(role)
                .createdBy(createdBy)
                .expiresAt(LocalDateTime.now().plusDays(Math.max(validDays != null ? validDays : defaultValidDays, 1)))
                .build();
        inviteRepository.save(invite);
        log.info("Invite created for role {} by {}", role, createdBy);
        return mapToDto(invite);
    }

    @Transactional(readOnly = true)
    public ValidateInviteResponse validate(String token) {
        if (token == null || token.isBlank()) {
            return new ValidateInviteResponse(false, null, "Invite token is required");
        }
        Invite invite = inviteRepository.findByToken(token).orElse(null);
        if (invite == null) {
            return new ValidateInviteResponse(false, null, "This invite link is invalid");
        }
        if (invite.getUsedAt() != null) {
            return new ValidateInviteResponse(false, invite.getRoleName(), "This invite has already been used");
        }
        if (!invite.getExpiresAt().isAfter(LocalDateTime.now())) {
            return new ValidateInviteResponse(false, invite.getRoleName(), "This invite has expired");
        }
        return new ValidateInviteResponse(true, invite.getRoleName(), null);
    }

    /**
     * Consumes a valid invite and returns the role it grants. Runs inside the
     * registration transaction, so a failed registration rolls the redemption
     * back and the invite stays usable.
     */
    @Transactional
    public String redeem(String token) {
        ValidateInviteResponse check = validate(token);
        if (!check.valid()) {
            throw new AuthException(check.message());
        }
        int updated = inviteRepository.markUsedIfAvailable(token, LocalDateTime.now());
        if (updated == 0) {
            // Lost a race against a concurrent registration using the same link.
            throw new AuthException("This invite has already been used");
        }
        return check.roleName();
    }

    @Transactional(readOnly = true)
    public List<InviteDto> listAll() {
        return inviteRepository.findAllByOrderByCreatedAtDesc().stream()
                .map(this::mapToDto)
                .toList();
    }

    @Transactional
    public void revoke(UUID inviteId) {
        Invite invite = inviteRepository.findById(inviteId)
                .orElseThrow(() -> new AuthException("Invite not found"));
        inviteRepository.delete(invite);
        log.info("Invite {} revoked", inviteId);
    }

    private String generateToken() {
        // 64 hex chars ≈ 256 bits of entropy — enough to be unguessable.
        return UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
    }

    private InviteDto mapToDto(Invite invite) {
        return new InviteDto(
                invite.getId(),
                invite.getToken(),
                invite.getRoleName(),
                invite.getCreatedAt(),
                invite.getExpiresAt(),
                invite.getUsedAt());
    }
}
