package io.contexa.contexaiam.repository;

import io.contexa.contexacommon.entity.behavior.BehaviorRealtimeCache;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

public interface BehaviorRealtimeCacheRepository extends JpaRepository<BehaviorRealtimeCache, String> {

    List<BehaviorRealtimeCache> findByCurrentRiskScoreGreaterThan(Float score);

    @Modifying
    @Transactional
    @Query("DELETE FROM BehaviorRealtimeCache b WHERE b.expiresAt < :now")
    int deleteByExpiresAtBefore(@Param("now") LocalDateTime now);
}
