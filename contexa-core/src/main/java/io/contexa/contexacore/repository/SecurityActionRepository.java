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


public interface SecurityActionRepository extends JpaRepository<SecurityAction, String> {
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.incident.incidentId = :incidentId")
    List<SecurityAction> findByIncidentId(@Param("incidentId") String incidentId);
    
    
    List<SecurityAction> findByStatus(SecurityAction.ActionStatus status);
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'PENDING' ORDER BY a.priority DESC, a.createdAt ASC")
    List<SecurityAction> findPendingActions();
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.approvalStatus = 'PENDING' AND a.requiresApproval = true")
    List<SecurityAction> findActionsAwaitingApproval();
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.approverId = :approverId AND a.approvalStatus = 'PENDING'")
    List<SecurityAction> findPendingApprovalsByUser(@Param("approverId") String approverId);
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'EXECUTING'")
    List<SecurityAction> findExecutingActions();
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'FAILED' AND a.retryCount < a.maxRetries")
    List<SecurityAction> findFailedActionsForRetry();
    
    
    List<SecurityAction> findByActionType(String actionType);
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.createdAt BETWEEN :startDate AND :endDate")
    List<SecurityAction> findActionsByDateRange(
        @Param("startDate") LocalDateTime startDate,
        @Param("endDate") LocalDateTime endDate
    );
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.scheduledAt <= :scheduledTime AND a.status = 'SCHEDULED'")
    List<SecurityAction> findScheduledActionsReady(@Param("scheduledTime") LocalDateTime scheduledTime);
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'FAILED' AND a.compensationActionId IS NOT NULL AND a.compensationExecuted = false")
    List<SecurityAction> findActionsNeedingCompensation();
    
    
    @Modifying
    @Query("UPDATE SecurityAction a SET a.status = :status, a.updatedAt = CURRENT_TIMESTAMP WHERE a.actionId = :actionId")
    int updateActionStatus(
        @Param("actionId") String actionId,
        @Param("status") SecurityAction.ActionStatus status
    );
    
    
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
    
    
    @Modifying
    @Query("UPDATE SecurityAction a SET a.retryCount = a.retryCount + 1, a.lastRetryAt = CURRENT_TIMESTAMP WHERE a.actionId = :actionId")
    int incrementRetryCount(@Param("actionId") String actionId);
    
    
    @Modifying
    @Query("UPDATE SecurityAction a SET a.compensationExecuted = true, a.compensationExecutedAt = CURRENT_TIMESTAMP WHERE a.actionId = :actionId")
    int markCompensationExecuted(@Param("actionId") String actionId);
    
    
    @Modifying
    @Query("UPDATE SecurityAction a SET a.status = 'EXPIRED' WHERE a.status IN ('PENDING', 'SCHEDULED') AND a.expiresAt < :expirationTime")
    int expireOldActions(@Param("expirationTime") LocalDateTime expirationTime);
    
    
    @Query("SELECT a.status, COUNT(a) FROM SecurityAction a WHERE a.incident.incidentId = :incidentId GROUP BY a.status")
    List<Object[]> getActionStatisticsByIncident(@Param("incidentId") String incidentId);
    
    
    @Query("SELECT a.approvalStatus, COUNT(a) FROM SecurityAction a " +
           "WHERE a.requiresApproval = true AND a.createdAt BETWEEN :startDate AND :endDate " +
           "GROUP BY a.approvalStatus")
    List<Object[]> getApprovalStatistics(
        @Param("startDate") LocalDateTime startDate,
        @Param("endDate") LocalDateTime endDate
    );
    
    
    @Query("SELECT AVG(a.executionDuration) FROM SecurityAction a WHERE a.actionType = :actionType AND a.status = 'COMPLETED'")
    Double getAverageExecutionTime(@Param("actionType") String actionType);
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'COMPLETED' ORDER BY a.executedAt DESC")
    List<SecurityAction> findRecentCompletedActions(Pageable pageable);
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'PENDING' AND a.priority = :priority ORDER BY a.createdAt ASC")
    List<SecurityAction> findPendingActionsByPriority(@Param("priority") int priority);
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.status = 'PENDING' AND a.requiresApproval = false AND a.autoExecute = true")
    List<SecurityAction> findAutoExecutableActions();
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.parentActionId = :parentActionId ORDER BY a.executionOrder ASC")
    List<SecurityAction> findChainedActions(@Param("parentActionId") String parentActionId);
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.incident.incidentId = :incidentId AND a.status = 'COMPLETED' AND a.rollbackable = true ORDER BY a.executedAt DESC")
    List<SecurityAction> findRollbackableActions(@Param("incidentId") String incidentId);
    
    
    @Query("SELECT a FROM SecurityAction a WHERE a.actionType = :actionType AND a.status IN ('COMPLETED', 'FAILED') ORDER BY a.executedAt DESC")
    List<SecurityAction> findExecutionHistory(
        @Param("actionType") String actionType,
        Pageable pageable
    );
}