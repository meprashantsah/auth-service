package com.prashant.auth_service.repository;

import com.prashant.auth_service.entity.Invite;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface InviteRepository extends JpaRepository<Invite, UUID> {

    Optional<Invite> findByToken(String token);

    List<Invite> findAllByOrderByCreatedAtDesc();

    /**
     * Single-use redemption: flips the invite to used only if it is still unused,
     * so two simultaneous registrations cannot both consume the same token.
     *
     * @return number of rows updated (0 when someone else won the race)
     */
    @Modifying
    @Query("""
            update Invite i
            set i.usedAt = :now
            where i.token = :token and i.usedAt is null
            """)
    int markUsedIfAvailable(@Param("token") String token, @Param("now") LocalDateTime now);
}
