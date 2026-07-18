package prashant.auth_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import prashant.auth_service.entity.User;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByPhoneNumber(String phoneNumber);
    Optional<User> findByUsername(String username);
    boolean existsByPhoneNumber(String phoneNumber);
    boolean existsByUsername(String username);

    @Query("SELECT u FROM User u WHERE u.phoneNumber = :identifier OR u.username = :identifier")
    Optional<User> findByPhoneNumberOrUsername(@Param("identifier") String identifier);
}