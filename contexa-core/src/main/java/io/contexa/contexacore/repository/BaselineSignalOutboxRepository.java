package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.BaselineSignalOutboxRecord;
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
public interface BaselineSignalOutboxRepository extends JpaRepository<BaselineSignalOutboxRecord, Long> {

    Optional<BaselineSignalOutboxRecord> findByPeriodStart(LocalDate periodStart);

    @Query("""
            select record
            from BaselineSignalOutboxRecord record
            where record.status in :statuses
              and record.periodStart < :currentPeriodStart
              and (record.nextAttemptAt is null or record.nextAttemptAt <= :now)
            order by record.periodStart asc
            """)
    List<BaselineSignalOutboxRecord> findDispatchableCompleted(
            @Param("statuses") List<String> statuses,
            @Param("currentPeriodStart") LocalDate currentPeriodStart,
            @Param("now") LocalDateTime now,
            Pageable pageable);
}
