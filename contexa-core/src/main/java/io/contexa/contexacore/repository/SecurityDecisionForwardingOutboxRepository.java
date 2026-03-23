package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface SecurityDecisionForwardingOutboxRepository extends JpaRepository<SecurityDecisionForwardingOutboxRecord, Long> {

    Optional<SecurityDecisionForwardingOutboxRecord> findByCorrelationId(String correlationId);

    @Query("""
            select record
            from SecurityDecisionForwardingOutboxRecord record
            where record.status in :statuses
              and (record.nextAttemptAt is null or record.nextAttemptAt <= :now)
            order by record.createdAt asc
            """)
    List<SecurityDecisionForwardingOutboxRecord> findDispatchable(
            @Param("statuses") List<String> statuses,
            @Param("now") LocalDateTime now,
            Pageable pageable);
}
