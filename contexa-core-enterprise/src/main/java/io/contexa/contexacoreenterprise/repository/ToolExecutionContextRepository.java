package io.contexa.contexacoreenterprise.repository;

import io.contexa.contexacoreenterprise.domain.entity.ToolExecutionContext;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface ToolExecutionContextRepository extends JpaRepository<ToolExecutionContext, Long> {

    Optional<ToolExecutionContext> findByRequestId(String requestId);

    List<ToolExecutionContext> findByIncidentIdOrderByCreatedAtDesc(String incidentId);

    List<ToolExecutionContext> findBySessionIdOrderByCreatedAtDesc(String sessionId);

    List<ToolExecutionContext> findByStatusOrderByCreatedAtAsc(String status);

    @Query("SELECT t FROM ToolExecutionContext t WHERE t.status = 'APPROVED' AND (t.expiresAt IS NULL OR t.expiresAt > :now) ORDER BY t.createdAt ASC")
    List<ToolExecutionContext> findExecutableContexts(@Param("now") LocalDateTime now);

    List<ToolExecutionContext> findByStatusOrderByExecutionStartTimeAsc(String status);

    @Query("SELECT t FROM ToolExecutionContext t WHERE t.status = 'FAILED' AND t.retryCount < t.maxRetries AND (t.expiresAt IS NULL OR t.expiresAt > :now)")
    List<ToolExecutionContext> findRetryableContexts(@Param("now") LocalDateTime now);

    @Query("SELECT t FROM ToolExecutionContext t WHERE t.expiresAt IS NOT NULL AND t.expiresAt < :now AND t.status IN ('PENDING', 'APPROVED')")
    List<ToolExecutionContext> findExpiredContexts(@Param("now") LocalDateTime now);

    List<ToolExecutionContext> findByToolNameOrderByCreatedAtDesc(String toolName);

    List<ToolExecutionContext> findByRiskLevelOrderByCreatedAtDesc(String riskLevel);

    @Modifying
    @Query("UPDATE ToolExecutionContext t SET t.status = :status, t.updatedAt = :now WHERE t.requestId = :requestId")
    void updateStatus(@Param("requestId") String requestId, @Param("status") String status, @Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE ToolExecutionContext t SET t.status = 'EXECUTING', t.executionStartTime = :now, t.updatedAt = :now WHERE t.requestId = :requestId")
    void markExecutionStart(@Param("requestId") String requestId, @Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE ToolExecutionContext t SET t.status = 'EXECUTED', t.executionEndTime = :now, t.executionResult = :result, t.updatedAt = :now WHERE t.requestId = :requestId")
    void markExecutionComplete(@Param("requestId") String requestId, @Param("result") String result, @Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE ToolExecutionContext t SET t.status = 'FAILED', t.executionEndTime = :now, t.executionError = :error, t.retryCount = t.retryCount + 1, t.updatedAt = :now WHERE t.requestId = :requestId")
    void markExecutionFailed(@Param("requestId") String requestId, @Param("error") String error, @Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE ToolExecutionContext t SET t.status = 'TIMEOUT', t.executionError = 'Expired', t.updatedAt = :now WHERE t.expiresAt IS NOT NULL AND t.expiresAt < :now AND t.status IN ('PENDING', 'APPROVED')")
    int cancelExpiredContexts(@Param("now") LocalDateTime now);

    @Query("SELECT t FROM ToolExecutionContext t WHERE t.createdAt BETWEEN :startDate AND :endDate ORDER BY t.createdAt DESC")
    List<ToolExecutionContext> findByDateRange(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    @Query("SELECT t FROM ToolExecutionContext t WHERE t.status IN ('EXECUTED', 'FAILED', 'CANCELLED', 'TIMEOUT') ORDER BY t.executionEndTime DESC")
    List<ToolExecutionContext> findCompletedContexts();

    @Query("SELECT t.toolName, COUNT(t), AVG(TIMESTAMPDIFF(SECOND, t.executionStartTime, t.executionEndTime)) FROM ToolExecutionContext t WHERE t.status = 'EXECUTED' GROUP BY t.toolName")
    List<Object[]> getToolExecutionStatistics();
}