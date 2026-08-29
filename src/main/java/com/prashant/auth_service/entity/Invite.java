package com.prashant.auth_service.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * A single-use workspace invite. The {@code token} is the shareable secret; the
 * {@code roleName} is fixed at creation so public registration can never choose
 * its own privileges. An invite is active until it is used or its
 * {@code expiresAt} passes.
 */
@Entity
@Table(name = "invites")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Invite {

    @Id
    private UUID id;

    @Column(unique = true, nullable = false, length = 64)
    private String token;

    @Column(name = "role_name", nullable = false, length = 50)
    private String roleName;

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    public boolean isActive() {
        return usedAt == null && expiresAt != null && expiresAt.isAfter(LocalDateTime.now());
    }
}
