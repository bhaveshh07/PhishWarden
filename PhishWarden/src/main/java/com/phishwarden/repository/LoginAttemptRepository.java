package com.phishwarden.repository;

import com.phishwarden.model.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    @Query("SELECT l.ipAddress FROM LoginAttempt l " +
           "WHERE l.emailUsed = :email AND l.wasSuccessful = true " +
           "GROUP BY l.ipAddress")
    List<String> findKnownIpsForEmail(@Param("email") String email);

    @Query("SELECT COUNT(l) FROM LoginAttempt l " +
           "WHERE l.ipAddress = :ip AND l.wasSuccessful = false " +
           "AND l.attemptedAt > :since")
    long countFailedSinceTime(@Param("ip") String ip,
                               @Param("since") LocalDateTime since);

    @Query("SELECT MAX(l.attemptedAt) FROM LoginAttempt l " +
           "WHERE l.ipAddress = :ip AND l.wasSuccessful = true")
    Optional<LocalDateTime> findLastSuccessTimeForIp(@Param("ip") String ip);

    @Query("SELECT MAX(l.attemptedAt) FROM LoginAttempt l " +
           "WHERE l.ipAddress = :ip AND l.wasSuccessful = false")
    Optional<LocalDateTime> findLastFailTimeForIp(@Param("ip") String ip);

    @Query("SELECT COUNT(l) FROM LoginAttempt l " +
           "WHERE l.emailUsed = :email " +
           "AND l.attemptedAt > :since")
    long countRecentLoginsForEmail(@Param("email") String email,
                                   @Param("since") LocalDateTime since);

    // ── Threat score query ────────────────────────────────────────
    @Query("SELECT COUNT(l) FROM LoginAttempt l " +
           "WHERE l.ipAddress = :ip AND l.wasSuccessful = false")
    long countFailedLoginsForIp(@Param("ip") String ip);
}