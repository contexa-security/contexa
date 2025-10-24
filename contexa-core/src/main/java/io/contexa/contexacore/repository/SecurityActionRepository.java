package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SecurityAction;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 보안 액션 리포지토리
 * 
 * JPA를 사용한 보안 액션 데이터 접근 계층입니다.
 * 승인 워크플로우와 실행 추적을 지원합니다.
 */
public interface SecurityActionRepository extends JpaRepository<SecurityAction, String> {
    
    /**
     * 인시던트별 액션 조회
     * 
     * @param incidentId 인시던트 ID
     * @return 해당 인시던트의 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.incident.incidentId = :incidentId")
    List<SecurityAction> findByIncidentId(@Param("incidentId") String incidentId);
    
    /**
     * 상태별 액션 조회
     * 
     * @param status 액션 상태
     * @return 해당 상태의 액션 리스트
     */
    List<SecurityAction> findByStatus(SecurityAction.ActionStatus status);
    
    /**
     * 대기 중인 액션 조회
     * 
     * @return 실행 대기 중인 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'PENDING' ORDER BY a.priority DESC, a.createdAt ASC")
    List<SecurityAction> findPendingActions();
    
    /**
     * 승인 대기 중인 액션 조회
     * 
     * @return 승인이 필요한 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.approvalStatus = 'PENDING' AND a.requiresApproval = true")
    List<SecurityAction> findActionsAwaitingApproval();
    
    /**
     * 사용자별 승인 대기 액션 조회
     * 
     * @param approverId 승인자 ID
     * @return 해당 사용자가 승인해야 할 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.approverId = :approverId AND a.approvalStatus = 'PENDING'")
    List<SecurityAction> findPendingApprovalsByUser(@Param("approverId") String approverId);
    
    /**
     * 실행 중인 액션 조회
     * 
     * @return 현재 실행 중인 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'EXECUTING'")
    List<SecurityAction> findExecutingActions();
    
    /**
     * 실패한 액션 조회
     * 
     * @return 실행 실패한 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'FAILED' AND a.retryCount < a.maxRetries")
    List<SecurityAction> findFailedActionsForRetry();
    
    /**
     * 타입별 액션 조회
     * 
     * @param actionType 액션 타입
     * @return 해당 타입의 액션 리스트
     */
    List<SecurityAction> findByActionType(String actionType);
    
    /**
     * 기간별 액션 조회
     * 
     * @param startDate 시작 날짜
     * @param endDate 종료 날짜
     * @return 해당 기간의 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.createdAt BETWEEN :startDate AND :endDate")
    List<SecurityAction> findActionsByDateRange(
        @Param("startDate") LocalDateTime startDate,
        @Param("endDate") LocalDateTime endDate
    );
    
    /**
     * 예약된 액션 조회
     * 
     * @param scheduledTime 예약 시간
     * @return 실행 예정인 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.scheduledAt <= :scheduledTime AND a.status = 'SCHEDULED'")
    List<SecurityAction> findScheduledActionsReady(@Param("scheduledTime") LocalDateTime scheduledTime);
    
    /**
     * 보상이 필요한 액션 조회
     * 
     * @return 보상 액션이 필요한 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'FAILED' AND a.compensationActionId IS NOT NULL AND a.compensationExecuted = false")
    List<SecurityAction> findActionsNeedingCompensation();
    
    /**
     * 액션 상태 업데이트
     * 
     * @param actionId 액션 ID
     * @param status 새로운 상태
     * @return 업데이트 성공 여부
     */
    @Modifying
    @Query("UPDATE SecurityAction a SET a.status = :status, a.updatedAt = CURRENT_TIMESTAMP WHERE a.actionId = :actionId")
    int updateActionStatus(
        @Param("actionId") String actionId,
        @Param("status") SecurityAction.ActionStatus status
    );
    
    /**
     * 액션 승인 상태 업데이트
     * 
     * @param actionId 액션 ID
     * @param approvalStatus 승인 상태
     * @param approverId 승인자 ID
     * @param approvalComment 승인 코멘트
     * @return 업데이트 성공 여부
     */
    @Modifying
    @Query("UPDATE SecurityAction a SET " +
           "a.approvalStatus = :approvalStatus, " +
           "a.approverId = :approverId, " +
           "a.approvalComment = :approvalComment, " +
           "a.approvedAt = CURRENT_TIMESTAMP, " +
           "a.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE a.actionId = :actionId")
    int updateApprovalStatus(
        @Param("actionId") String actionId,
        @Param("approvalStatus") SecurityAction.ApprovalStatus approvalStatus,
        @Param("approverId") String approverId,
        @Param("approvalComment") String approvalComment
    );
    
    /**
     * 실행 결과 업데이트
     * 
     * @param actionId 액션 ID
     * @param result 실행 결과
     * @param output 실행 출력
     * @return 업데이트 성공 여부
     */
    @Modifying
    @Query("UPDATE SecurityAction a SET " +
           "a.executionResult = :result, " +
           "a.executionOutput = :output, " +
           "a.executedAt = CURRENT_TIMESTAMP, " +
           "a.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE a.actionId = :actionId")
    int updateExecutionResult(
        @Param("actionId") String actionId,
        @Param("result") String result,
        @Param("output") String output
    );
    
    /**
     * 재시도 횟수 증가
     * 
     * @param actionId 액션 ID
     * @return 업데이트 성공 여부
     */
    @Modifying
    @Query("UPDATE SecurityAction a SET a.retryCount = a.retryCount + 1, a.lastRetryAt = CURRENT_TIMESTAMP WHERE a.actionId = :actionId")
    int incrementRetryCount(@Param("actionId") String actionId);
    
    /**
     * 보상 실행 표시
     * 
     * @param actionId 액션 ID
     * @return 업데이트 성공 여부
     */
    @Modifying
    @Query("UPDATE SecurityAction a SET a.compensationExecuted = true, a.compensationExecutedAt = CURRENT_TIMESTAMP WHERE a.actionId = :actionId")
    int markCompensationExecuted(@Param("actionId") String actionId);
    
    /**
     * 만료된 액션 처리
     * 
     * @param expirationTime 만료 기준 시간
     * @return 처리된 액션 수
     */
    @Modifying
    @Query("UPDATE SecurityAction a SET a.status = 'EXPIRED' WHERE a.status IN ('PENDING', 'SCHEDULED') AND a.expiresAt < :expirationTime")
    int expireOldActions(@Param("expirationTime") LocalDateTime expirationTime);
    
    /**
     * 액션 통계 조회
     * 
     * @param incidentId 인시던트 ID
     * @return 상태별 액션 수
     */
    @Query("SELECT a.status, COUNT(a) FROM SecurityAction a WHERE a.incident.incidentId = :incidentId GROUP BY a.status")
    List<Object[]> getActionStatisticsByIncident(@Param("incidentId") String incidentId);
    
    /**
     * 승인 통계 조회
     * 
     * @param startDate 시작 날짜
     * @param endDate 종료 날짜
     * @return 승인 상태별 통계
     */
    @Query("SELECT a.approvalStatus, COUNT(a) FROM SecurityAction a " +
           "WHERE a.requiresApproval = true AND a.createdAt BETWEEN :startDate AND :endDate " +
           "GROUP BY a.approvalStatus")
    List<Object[]> getApprovalStatistics(
        @Param("startDate") LocalDateTime startDate,
        @Param("endDate") LocalDateTime endDate
    );
    
    /**
     * 평균 실행 시간 조회
     * 
     * @param actionType 액션 타입
     * @return 평균 실행 시간 (밀리초)
     */
    @Query("SELECT AVG(a.executionDuration) FROM SecurityAction a WHERE a.actionType = :actionType AND a.status = 'COMPLETED'")
    Double getAverageExecutionTime(@Param("actionType") String actionType);
    
    /**
     * 최근 완료된 액션 조회
     * 
     * @param pageable 페이지 정보
     * @return 최근 완료된 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'COMPLETED' ORDER BY a.executedAt DESC")
    List<SecurityAction> findRecentCompletedActions(Pageable pageable);
    
    /**
     * 우선순위별 대기 액션 조회
     * 
     * @param priority 우선순위
     * @return 해당 우선순위의 대기 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'PENDING' AND a.priority = :priority ORDER BY a.createdAt ASC")
    List<SecurityAction> findPendingActionsByPriority(@Param("priority") int priority);
    
    /**
     * 자동 실행 가능한 액션 조회
     * 
     * @return 자동 실행 가능한 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'PENDING' AND a.requiresApproval = false AND a.autoExecute = true")
    List<SecurityAction> findAutoExecutableActions();
    
    /**
     * 체인된 액션 조회
     * 
     * @param parentActionId 부모 액션 ID
     * @return 체인된 자식 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.parentActionId = :parentActionId ORDER BY a.executionOrder ASC")
    List<SecurityAction> findChainedActions(@Param("parentActionId") String parentActionId);
    
    /**
     * 롤백 가능한 액션 조회
     * 
     * @param incidentId 인시던트 ID
     * @return 롤백 가능한 액션 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.incident.incidentId = :incidentId AND a.status = 'COMPLETED' AND a.rollbackable = true ORDER BY a.executedAt DESC")
    List<SecurityAction> findRollbackableActions(@Param("incidentId") String incidentId);
    
    /**
     * 실행 이력 조회
     * 
     * @param actionType 액션 타입
     * @param pageable 페이지 정보
     * @return 실행 이력 리스트
     */
    @Query("SELECT a FROM SecurityAction a WHERE a.actionType = :actionType AND a.status IN ('COMPLETED', 'FAILED') ORDER BY a.executedAt DESC")
    List<SecurityAction> findExecutionHistory(
        @Param("actionType") String actionType,
        Pageable pageable
    );
}