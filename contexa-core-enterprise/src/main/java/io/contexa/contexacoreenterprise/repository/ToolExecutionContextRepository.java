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

/**
 * Tool Execution Context Repository
 * 
 * 도구 실행 컨텍스트 데이터 접근 계층
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
@Repository
public interface ToolExecutionContextRepository extends JpaRepository<ToolExecutionContext, Long> {
    
    /**
     * 요청 ID로 컨텍스트 조회
     */
    Optional<ToolExecutionContext> findByRequestId(String requestId);
    
    /**
     * 인시던트 ID로 컨텍스트 목록 조회
     */
    List<ToolExecutionContext> findByIncidentIdOrderByCreatedAtDesc(String incidentId);
    
    /**
     * 세션 ID로 컨텍스트 목록 조회
     */
    List<ToolExecutionContext> findBySessionIdOrderByCreatedAtDesc(String sessionId);
    
    /**
     * 상태별 컨텍스트 조회
     */
    List<ToolExecutionContext> findByStatusOrderByCreatedAtAsc(String status);
    
    /**
     * 실행 대기 중인 컨텍스트 조회 (APPROVED 상태)
     */
    @Query("SELECT t FROM ToolExecutionContext t WHERE t.status = 'APPROVED' AND (t.expiresAt IS NULL OR t.expiresAt > :now) ORDER BY t.createdAt ASC")
    List<ToolExecutionContext> findExecutableContexts(@Param("now") LocalDateTime now);
    
    /**
     * 실행 중인 컨텍스트 조회
     */
    List<ToolExecutionContext> findByStatusOrderByExecutionStartTimeAsc(String status);
    
    /**
     * 재시도 가능한 컨텍스트 조회
     */
    @Query("SELECT t FROM ToolExecutionContext t WHERE t.status = 'FAILED' AND t.retryCount < t.maxRetries AND (t.expiresAt IS NULL OR t.expiresAt > :now)")
    List<ToolExecutionContext> findRetryableContexts(@Param("now") LocalDateTime now);
    
    /**
     * 만료된 컨텍스트 조회
     */
    @Query("SELECT t FROM ToolExecutionContext t WHERE t.expiresAt IS NOT NULL AND t.expiresAt < :now AND t.status IN ('PENDING', 'APPROVED')")
    List<ToolExecutionContext> findExpiredContexts(@Param("now") LocalDateTime now);
    
    /**
     * 도구 이름별 컨텍스트 조회
     */
    List<ToolExecutionContext> findByToolNameOrderByCreatedAtDesc(String toolName);
    
    /**
     * 위험 수준별 컨텍스트 조회
     */
    List<ToolExecutionContext> findByRiskLevelOrderByCreatedAtDesc(String riskLevel);
    
    /**
     * 상태 업데이트
     */
    @Modifying
    @Query("UPDATE ToolExecutionContext t SET t.status = :status, t.updatedAt = :now WHERE t.requestId = :requestId")
    void updateStatus(@Param("requestId") String requestId, @Param("status") String status, @Param("now") LocalDateTime now);
    
    /**
     * 실행 시작 표시
     */
    @Modifying
    @Query("UPDATE ToolExecutionContext t SET t.status = 'EXECUTING', t.executionStartTime = :now, t.updatedAt = :now WHERE t.requestId = :requestId")
    void markExecutionStart(@Param("requestId") String requestId, @Param("now") LocalDateTime now);
    
    /**
     * 실행 완료 표시
     */
    @Modifying
    @Query("UPDATE ToolExecutionContext t SET t.status = 'EXECUTED', t.executionEndTime = :now, t.executionResult = :result, t.updatedAt = :now WHERE t.requestId = :requestId")
    void markExecutionComplete(@Param("requestId") String requestId, @Param("result") String result, @Param("now") LocalDateTime now);
    
    /**
     * 실행 실패 표시
     */
    @Modifying
    @Query("UPDATE ToolExecutionContext t SET t.status = 'FAILED', t.executionEndTime = :now, t.executionError = :error, t.retryCount = t.retryCount + 1, t.updatedAt = :now WHERE t.requestId = :requestId")
    void markExecutionFailed(@Param("requestId") String requestId, @Param("error") String error, @Param("now") LocalDateTime now);
    
    /**
     * 만료된 컨텍스트 자동 취소
     */
    @Modifying
    @Query("UPDATE ToolExecutionContext t SET t.status = 'TIMEOUT', t.executionError = 'Expired', t.updatedAt = :now WHERE t.expiresAt IS NOT NULL AND t.expiresAt < :now AND t.status IN ('PENDING', 'APPROVED')")
    int cancelExpiredContexts(@Param("now") LocalDateTime now);
    
    /**
     * 날짜 범위로 컨텍스트 조회
     */
    @Query("SELECT t FROM ToolExecutionContext t WHERE t.createdAt BETWEEN :startDate AND :endDate ORDER BY t.createdAt DESC")
    List<ToolExecutionContext> findByDateRange(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);
    
    /**
     * 실행 완료된 컨텍스트 조회
     */
    @Query("SELECT t FROM ToolExecutionContext t WHERE t.status IN ('EXECUTED', 'FAILED', 'CANCELLED', 'TIMEOUT') ORDER BY t.executionEndTime DESC")
    List<ToolExecutionContext> findCompletedContexts();
    
    /**
     * 도구별 실행 통계
     */
    @Query("SELECT t.toolName, COUNT(t), AVG(TIMESTAMPDIFF(SECOND, t.executionStartTime, t.executionEndTime)) FROM ToolExecutionContext t WHERE t.status = 'EXECUTED' GROUP BY t.toolName")
    List<Object[]> getToolExecutionStatistics();
}