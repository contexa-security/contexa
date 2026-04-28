package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.LoginAttemptIp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Per-IP login attempt counters with atomic operations to avoid race conditions.
 * All mutating queries are single-statement UPDATEs for concurrency safety.
 */
public interface LoginAttemptIpRepository extends JpaRepository<LoginAttemptIp, Long> {

    Optional<LoginAttemptIp> findByIpAddress(String ipAddress);

    /**
     * Atomically increment the per-IP failed-attempt counter.
     * Returns 0 if the IP has no row yet (caller must insert via upsert).
     * <p>flushAutomatically/clearAutomatically keep the persistence context in sync so a follow-up
     * {@link #findByIpAddress(String)} in the same transaction returns the updated row.</p>
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE LoginAttemptIp a SET a.failedAttempts = a.failedAttempts + 1, " +
            "a.lastFailureAt = :now, a.lastUsername = :username WHERE a.ipAddress = :ip")
    int incrementFailedAttempts(@Param("ip") String ip,
                                 @Param("now") LocalDateTime now,
                                 @Param("username") String username);

    /**
     * Atomically reset the per-IP counter window.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE LoginAttemptIp a SET a.failedAttempts = 1, a.windowStartAt = :windowStart, " +
            "a.lastFailureAt = :now, a.lastUsername = :username WHERE a.ipAddress = :ip")
    int resetWindow(@Param("ip") String ip,
                    @Param("windowStart") LocalDateTime windowStart,
                    @Param("now") LocalDateTime now,
                    @Param("username") String username);

    /**
     * Atomically set blockedUntil for an IP.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE LoginAttemptIp a SET a.blockedUntil = :blockedUntil WHERE a.ipAddress = :ip")
    int blockIp(@Param("ip") String ip, @Param("blockedUntil") LocalDateTime blockedUntil);

    /**
     * Atomically clear an expired block (idempotent self-heal).
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE LoginAttemptIp a SET a.blockedUntil = null, a.failedAttempts = 0 " +
            "WHERE a.ipAddress = :ip AND a.blockedUntil IS NOT NULL AND a.blockedUntil < :now")
    int clearExpiredBlock(@Param("ip") String ip, @Param("now") LocalDateTime now);
}
