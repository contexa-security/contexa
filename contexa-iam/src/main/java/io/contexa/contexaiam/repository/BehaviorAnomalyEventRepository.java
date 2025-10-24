package io.contexa.contexaiam.repository;

import io.contexa.contexacommon.entity.behavior.BehaviorAnomalyEvent;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface BehaviorAnomalyEventRepository extends JpaRepository<BehaviorAnomalyEvent, Long> {

    @Query("SELECT COUNT(DISTINCT b.userId) FROM BehaviorAnomalyEvent b " +
            "WHERE b.eventTimestamp BETWEEN :start AND :end")
    long countDistinctUsersByEventTimestampBetween(@Param("start") LocalDateTime start,
                                                   @Param("end") LocalDateTime end);

    long countByEventTimestampAfter(LocalDateTime timestamp);

    List<BehaviorAnomalyEvent> findByEventTimestampAfter(LocalDateTime timestamp);

    List<BehaviorAnomalyEvent> findByRiskLevelIn(List<String> riskLevels, Pageable pageable);

    List<BehaviorAnomalyEvent> findByUserId(String userId);

    List<BehaviorAnomalyEvent> findByUserIdAndEventTimestampAfter(String userId, LocalDateTime timestamp);

    List<BehaviorAnomalyEvent> findByUserIdAndEventTimestampAfter(String userId, LocalDateTime timestamp, Pageable pageable);

    Optional<BehaviorAnomalyEvent> findByAiAnalysisId(String analysisId);
}
