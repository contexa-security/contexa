package io.contexa.contexacore.domain.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.contexa.contexacore.utils.JpaMapConverter;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.Map;

@Entity
@Table(name = "approval_notifications", indexes = {
    @Index(name = "idx_notification_request_id", columnList = "request_id"),
    @Index(name = "idx_notification_user_id", columnList = "user_id"),
    @Index(name = "idx_notification_is_read", columnList = "is_read"),
    @Index(name = "idx_notification_created_at", columnList = "created_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class ApprovalNotification {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_id", nullable = false, length = 100)
    private String requestId;

    @Column(name = "notification_type", nullable = false, length = 50)
    private String notificationType;

    @Column(name = "title", nullable = false, length = 255)
    private String title;

    @Column(name = "message", columnDefinition = "TEXT")
    private String message;

    @Column(name = "user_id", length = 100)
    private String userId;

    @Column(name = "target_role", length = 50)
    private String targetRole;

    @Column(name = "is_read", nullable = false)
    @Builder.Default
    private Boolean isRead = false;

    @Column(name = "read_at")
    private LocalDateTime readAt;

    @Column(name = "read_by", length = 100)
    private String readBy;

    @Column(name = "priority", length = 20)
    @Builder.Default
    private String priority = "MEDIUM";

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Convert(converter = JpaMapConverter.class)
    @Column(name = "notification_data", columnDefinition = "TEXT")
    private Map<String, Object> notificationData;

    @Column(name = "action_required", nullable = false)
    @Builder.Default
    private Boolean actionRequired = false;

    @Column(name = "action_url", length = 500)
    private String actionUrl;

    @Column(name = "group_id", length = 100)
    private String groupId;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public void markAsRead(String userId) {
        this.isRead = true;
        this.readAt = LocalDateTime.now();
        this.readBy = userId;
    }

    @JsonIgnore
    public boolean isExpired() {
        return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
    }

    @JsonIgnore
    public boolean isHighPriority() {
        return "CRITICAL".equals(priority) || "HIGH".equals(priority);
    }

    public enum NotificationType {
        APPROVAL_REQUEST("Approval Request"),
        APPROVAL_GRANTED("Approved"),
        APPROVAL_REJECTED("Rejected"),
        APPROVAL_TIMEOUT("Timeout"),
        TOOL_EXECUTED("Tool Executed"),
        TOOL_FAILED("Tool Execution Failed");
        
        private final String description;
        
        NotificationType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
}