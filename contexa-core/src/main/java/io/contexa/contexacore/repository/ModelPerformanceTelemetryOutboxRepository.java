package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.ModelPerformanceTelemetryOutboxRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface ModelPerformanceTelemetryOutboxRepository extends JpaRepository<ModelPerformanceTelemetryOutboxRecord, Long> {

    Optional<ModelPerformanceTelemetryOutboxRecord> findByPeriod(LocalDate period);

    Optional<ModelPerformanceTelemetryOutboxRecord> findTopByOrderByPeriodDesc();

    @Query("""
            select record
            from ModelPerformanceTelemetryOutboxRecord record
            where record.status in :statuses
              and record.period < :today
              and (record.nextAttemptAt is null or record.nextAttemptAt <= :now)
            order by record.period asc
            """)
    List<ModelPerformanceTelemetryOutboxRecord> findDispatchableCompleted(
            @Param("statuses") List<String> statuses,
            @Param("today") LocalDate today,
            @Param("now") LocalDateTime now,
            Pageable pageable);
}
