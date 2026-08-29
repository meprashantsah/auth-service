package com.prashant.auth_service.service;

import com.prashant.auth_service.dto.InviteDto;
import com.prashant.auth_service.entity.Invite;
import com.prashant.auth_service.exception.AuthException;
import com.prashant.auth_service.repository.InviteRepository;
import com.prashant.auth_service.repository.RoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class InviteServiceTest {

    @Mock
    private InviteRepository inviteRepository;
    @Mock
    private RoleRepository roleRepository;

    private InviteService inviteService;

    private UUID actorId;

    @BeforeEach
    void setUp() {
        inviteService = new InviteService(inviteRepository, roleRepository);
        actorId = UUID.randomUUID();
    }

    @Test
    void create_savesInviteWithFixedRole() {
        when(roleRepository.existsByName("ADMIN")).thenReturn(true);
        when(inviteRepository.save(any(Invite.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        InviteDto dto = inviteService.create(actorId, "ADMIN", 7);

        assertThat(dto.roleName()).isEqualTo("ADMIN");
        assertThat(dto.token()).hasSize(64);
        assertThat(dto.usedAt()).isNull();
        assertThat(dto.expiresAt()).isAfter(LocalDateTime.now());
        verify(inviteRepository).save(any(Invite.class));
    }

    @Test
    void create_rejectsUnknownRole() {
        when(roleRepository.existsByName("NOPE")).thenReturn(false);

        assertThatThrownBy(() -> inviteService.create(actorId, "NOPE", 7))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("NOPE");
        verify(inviteRepository, never()).save(any());
    }

    @Test
    void validate_returnsInvalidForUnknownToken() {
        when(inviteRepository.findByToken("nope")).thenReturn(Optional.empty());

        var result = inviteService.validate("nope");

        assertThat(result.valid()).isFalse();
        assertThat(result.message()).contains("invalid");
    }

    @Test
    void validate_returnsValidForActiveInvite() {
        Invite invite = activeInvite("tok-1", "ADMIN");
        when(inviteRepository.findByToken("tok-1")).thenReturn(Optional.of(invite));

        var result = inviteService.validate("tok-1");

        assertThat(result.valid()).isTrue();
        assertThat(result.roleName()).isEqualTo("ADMIN");
    }

    @Test
    void validate_returnsUsedForConsumedInvite() {
        Invite invite = activeInvite("tok-1", "ADMIN");
        invite.setUsedAt(LocalDateTime.now().minusHours(1));
        when(inviteRepository.findByToken("tok-1")).thenReturn(Optional.of(invite));

        var result = inviteService.validate("tok-1");

        assertThat(result.valid()).isFalse();
        assertThat(result.message()).contains("used");
    }

    @Test
    void validate_returnsExpiredForStaleInvite() {
        Invite invite = activeInvite("tok-1", "ADMIN");
        invite.setExpiresAt(LocalDateTime.now().minusDays(1));
        when(inviteRepository.findByToken("tok-1")).thenReturn(Optional.of(invite));

        var result = inviteService.validate("tok-1");

        assertThat(result.valid()).isFalse();
        assertThat(result.message()).contains("expired");
    }

    @Test
    void redeem_marksInviteUsedAndReturnsRole() {
        when(inviteRepository.findByToken("tok-1")).thenReturn(Optional.of(activeInvite("tok-1", "ADMIN")));
        when(inviteRepository.markUsedIfAvailable(org.mockito.ArgumentMatchers.eq("tok-1"), any())).thenReturn(1);

        String role = inviteService.redeem("tok-1");

        assertThat(role).isEqualTo("ADMIN");
        verify(inviteRepository).markUsedIfAvailable(org.mockito.ArgumentMatchers.eq("tok-1"), any());
    }

    @Test
    void redeem_failsWhenAnotherRegistrationWonTheRace() {
        when(inviteRepository.findByToken("tok-1")).thenReturn(Optional.of(activeInvite("tok-1", "ADMIN")));
        when(inviteRepository.markUsedIfAvailable(org.mockito.ArgumentMatchers.eq("tok-1"), any())).thenReturn(0);

        assertThatThrownBy(() -> inviteService.redeem("tok-1"))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("used");
    }

    private Invite activeInvite(String token, String roleName) {
        return Invite.builder()
                .id(UUID.randomUUID())
                .token(token)
                .roleName(roleName)
                .createdBy(actorId)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();
    }
}
