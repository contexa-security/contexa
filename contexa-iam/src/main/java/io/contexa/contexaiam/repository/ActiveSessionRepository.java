package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.ActiveSession;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface ActiveSessionRepository extends JpaRepository<ActiveSession, String> {

    List<ActiveSession> findByExpiredFalseOrderByLastAccessedAtDesc();

    List<ActiveSession> findByUserIdAndExpiredFalse(String userId);

    long countByExpiredFalse();

    long countByUserId(String userId);

    @Modifying
    @Query("UPDATE ActiveSession s SET s.expired = true WHERE s.sessionId = :sessionId")
    void expireSession(@Param("sessionId") String sessionId);

    @Modifying
    @Query("UPDATE ActiveSession s SET s.expired = true WHERE s.userId = :userId")
    void expireAllSessionsForUser(@Param("userId") String userId);

    @Modifying
    @Query("DELETE FROM ActiveSession s WHERE s.expired = true AND s.lastAccessedAt < :before")
    void deleteExpiredBefore(@Param("before") LocalDateTime before);

    Page<ActiveSession> findByExpiredFalse(Pageable pageable);
}
