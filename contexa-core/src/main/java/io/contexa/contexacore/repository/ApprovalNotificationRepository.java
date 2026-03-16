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

@Repository
public interface ApprovalNotificationRepository extends JpaRepository<ApprovalNotification, Long> {

    List<ApprovalNotification> findByRequestId(String requestId);

    List<ApprovalNotification> findByUserIdAndIsReadFalseOrderByCreatedAtDesc(String userId);

    List<ApprovalNotification> findByTargetRoleAndIsReadFalseOrderByCreatedAtDesc(String targetRole);

    List<ApprovalNotification> findByIsReadFalseOrderByCreatedAtDesc();

    List<ApprovalNotification> findTop10ByIsReadFalseOrderByCreatedAtDesc();

    long countByUserIdAndIsReadFalse(String userId);

    long countByIsReadFalse();

    @Query("SELECT n FROM ApprovalNotification n WHERE n.userId = :userId AND n.priority IN :priorities AND n.isRead = false ORDER BY n.createdAt DESC")
    List<ApprovalNotification> findByUserIdAndPriorities(@Param("userId") String userId, @Param("priorities") List<String> priorities);

    List<ApprovalNotification> findByUserIdAndActionRequiredTrueAndIsReadFalseOrderByCreatedAtDesc(String userId);

    @Query("SELECT n FROM ApprovalNotification n WHERE n.expiresAt IS NOT NULL AND n.expiresAt < :now AND n.isRead = false")
    List<ApprovalNotification> findExpiredNotifications(@Param("now") LocalDateTime now);

    List<ApprovalNotification> findByGroupIdOrderByCreatedAtDesc(String groupId);

    @Modifying
    @Query("UPDATE ApprovalNotification n SET n.isRead = true, n.readAt = :readAt, n.readBy = :userId WHERE n.id = :id")
    void markAsRead(@Param("id") Long id, @Param("readAt") LocalDateTime readAt, @Param("userId") String userId);

    @Modifying
    @Query("UPDATE ApprovalNotification n SET n.isRead = true, n.readAt = :readAt, n.readBy = :userId WHERE n.requestId = :requestId")
    void markAllAsReadByRequestId(@Param("requestId") String requestId, @Param("readAt") LocalDateTime readAt, @Param("userId") String userId);

    @Modifying
    @Query("UPDATE ApprovalNotification n SET n.isRead = true, n.readAt = :now WHERE n.expiresAt IS NOT NULL AND n.expiresAt < :now AND n.isRead = false")
    int processExpiredNotifications(@Param("now") LocalDateTime now);

    @Query("SELECT n FROM ApprovalNotification n WHERE n.createdAt BETWEEN :startDate AND :endDate ORDER BY n.createdAt DESC")
    List<ApprovalNotification> findByDateRange(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    List<ApprovalNotification> findByNotificationTypeOrderByCreatedAtDesc(String notificationType);

    Optional<ApprovalNotification> findTopByUserIdAndNotificationTypeOrderByCreatedAtDesc(String userId, String notificationType);
}