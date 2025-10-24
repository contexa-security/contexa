package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.ApprovalNotification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Approval Notification Repository
 * 
 * 승인 알림 데이터 접근 계층
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
@Repository
public interface ApprovalNotificationRepository extends JpaRepository<ApprovalNotification, Long> {
    
    /**
     * 요청 ID로 알림 조회
     */
    List<ApprovalNotification> findByRequestId(String requestId);
    
    /**
     * 사용자 ID로 읽지 않은 알림 조회
     */
    List<ApprovalNotification> findByUserIdAndIsReadFalseOrderByCreatedAtDesc(String userId);
    
    /**
     * 역할로 읽지 않은 알림 조회
     */
    List<ApprovalNotification> findByTargetRoleAndIsReadFalseOrderByCreatedAtDesc(String targetRole);
    
    /**
     * 모든 읽지 않은 알림 조회 (관리자용)
     */
    List<ApprovalNotification> findByIsReadFalseOrderByCreatedAtDesc();
    
    /**
     * 사용자의 알림 개수 조회
     */
    long countByUserIdAndIsReadFalse(String userId);
    
    /**
     * 우선순위별 알림 조회
     */
    @Query("SELECT n FROM ApprovalNotification n WHERE n.userId = :userId AND n.priority IN :priorities AND n.isRead = false ORDER BY n.createdAt DESC")
    List<ApprovalNotification> findByUserIdAndPriorities(@Param("userId") String userId, @Param("priorities") List<String> priorities);
    
    /**
     * 액션 필요한 알림 조회
     */
    List<ApprovalNotification> findByUserIdAndActionRequiredTrueAndIsReadFalseOrderByCreatedAtDesc(String userId);
    
    /**
     * 만료된 알림 조회
     */
    @Query("SELECT n FROM ApprovalNotification n WHERE n.expiresAt IS NOT NULL AND n.expiresAt < :now AND n.isRead = false")
    List<ApprovalNotification> findExpiredNotifications(@Param("now") LocalDateTime now);
    
    /**
     * 그룹별 알림 조회
     */
    List<ApprovalNotification> findByGroupIdOrderByCreatedAtDesc(String groupId);
    
    /**
     * 알림을 읽음으로 표시
     */
    @Modifying
    @Query("UPDATE ApprovalNotification n SET n.isRead = true, n.readAt = :readAt, n.readBy = :userId WHERE n.id = :id")
    void markAsRead(@Param("id") Long id, @Param("readAt") LocalDateTime readAt, @Param("userId") String userId);
    
    /**
     * 요청 ID의 모든 알림을 읽음으로 표시
     */
    @Modifying
    @Query("UPDATE ApprovalNotification n SET n.isRead = true, n.readAt = :readAt, n.readBy = :userId WHERE n.requestId = :requestId")
    void markAllAsReadByRequestId(@Param("requestId") String requestId, @Param("readAt") LocalDateTime readAt, @Param("userId") String userId);
    
    /**
     * 만료된 알림 자동 처리
     */
    @Modifying
    @Query("UPDATE ApprovalNotification n SET n.isRead = true, n.readAt = :now WHERE n.expiresAt IS NOT NULL AND n.expiresAt < :now AND n.isRead = false")
    int processExpiredNotifications(@Param("now") LocalDateTime now);
    
    /**
     * 날짜 범위로 알림 조회
     */
    @Query("SELECT n FROM ApprovalNotification n WHERE n.createdAt BETWEEN :startDate AND :endDate ORDER BY n.createdAt DESC")
    List<ApprovalNotification> findByDateRange(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);
    
    /**
     * 알림 유형별 조회
     */
    List<ApprovalNotification> findByNotificationTypeOrderByCreatedAtDesc(String notificationType);
    
    /**
     * 사용자와 알림 유형으로 조회
     */
    Optional<ApprovalNotification> findTopByUserIdAndNotificationTypeOrderByCreatedAtDesc(String userId, String notificationType);
}