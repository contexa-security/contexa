package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface SecurityDecisionForwardingOutboxRepository extends JpaRepository<SecurityDecisionForwardingOutboxRecord, Long> {

    Optional<SecurityDecisionForwardingOutboxRecord> findByCorrelationId(String correlationId);

    Optional<SecurityDecisionForwardingOutboxRecord> findTopByCorrelationIdOrderByIdDesc(String correlationId);

    @Query("""
            select record.id
            from SecurityDecisionForwardingOutboxRecord record
            where record.status in :statuses
              and (record.nextAttemptAt is null or record.nextAttemptAt <= :now)
            order by record.createdAt asc
            """)
    List<Long> findDispatchableIds(
            @Param("statuses") List<String> statuses,
            @Param("now") LocalDateTime now,
            Pageable pageable);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional(transactionManager = "contexaTransactionManager")
    @Query("""
            update SecurityDecisionForwardingOutboxRecord record
               set record.status = :dispatchingStatus,
                   record.attemptCount = coalesce(record.attemptCount, 0) + 1,
                   record.version = record.version + 1,
                   record.lastError = null,
                   record.updatedAt = :now
             where record.id = :id
               and record.status in :statuses
               and (record.nextAttemptAt is null or record.nextAttemptAt <= :now)
            """)
    int claimForDispatch(
            @Param("id") Long id,
            @Param("statuses") List<String> statuses,
            @Param("dispatchingStatus") String dispatchingStatus,
            @Param("now") LocalDateTime now);
}
