package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface PromptContextAuditForwardingOutboxRepository extends JpaRepository<PromptContextAuditForwardingOutboxRecord, Long> {

    Optional<PromptContextAuditForwardingOutboxRecord> findByAuditId(String auditId);

    Optional<PromptContextAuditForwardingOutboxRecord> findByCorrelationId(String correlationId);

    @Query("""
            select record
            from PromptContextAuditForwardingOutboxRecord record
            where record.status in :statuses
              and (record.nextAttemptAt is null or record.nextAttemptAt <= :now)
            order by record.createdAt asc
            """)
    List<PromptContextAuditForwardingOutboxRecord> findDispatchable(
            @Param("statuses") List<String> statuses,
            @Param("now") LocalDateTime now,
            Pageable pageable);
}
