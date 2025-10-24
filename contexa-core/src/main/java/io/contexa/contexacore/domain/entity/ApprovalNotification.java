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

/**
 * Approval Notification Entity
 * 
 * 승인 알림을 데이터베이스에 영속화하기 위한 엔티티입니다.
 * Agent 기반 비동기 처리에서 WebSocket 대신 DB에 알림을 저장합니다.
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
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
    
    /**
     * 승인 요청 ID
     * SoarApprovalRequest와 연결
     */
    @Column(name = "request_id", nullable = false, length = 100)
    private String requestId;
    
    /**
     * 알림 유형
     * APPROVAL_REQUEST: 승인 요청
     * APPROVAL_GRANTED: 승인됨
     * APPROVAL_REJECTED: 거부됨
     * APPROVAL_TIMEOUT: 타임아웃
     * TOOL_EXECUTED: 도구 실행됨
     * TOOL_FAILED: 도구 실행 실패
     */
    @Column(name = "notification_type", nullable = false, length = 50)
    private String notificationType;
    
    /**
     * 알림 제목
     */
    @Column(name = "title", nullable = false, length = 255)
    private String title;
    
    /**
     * 알림 메시지
     */
    @Column(name = "message", columnDefinition = "TEXT")
    private String message;
    
    /**
     * 알림 대상 사용자 ID
     * null이면 모든 관리자에게 표시
     */
    @Column(name = "user_id", length = 100)
    private String userId;
    
    /**
     * 알림 대상 역할
     * ROLE_ADMIN, ROLE_SECURITY_OFFICER 등
     */
    @Column(name = "target_role", length = 50)
    private String targetRole;
    
    /**
     * 읽음 여부
     */
    @Column(name = "is_read", nullable = false)
    @Builder.Default
    private Boolean isRead = false;
    
    /**
     * 읽은 시간
     */
    @Column(name = "read_at")
    private LocalDateTime readAt;
    
    /**
     * 읽은 사용자 ID
     */
    @Column(name = "read_by", length = 100)
    private String readBy;
    
    /**
     * 우선순위
     * CRITICAL, HIGH, MEDIUM, LOW, INFO
     */
    @Column(name = "priority", length = 20)
    @Builder.Default
    private String priority = "MEDIUM";
    
    /**
     * 만료 시간
     * 이 시간 이후에는 자동으로 읽음 처리
     */
    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
    
    /**
     * 알림 데이터 (JSON)
     * 도구 정보, 위험 수준, 컨텍스트 등
     */
    @Convert(converter = JpaMapConverter.class)
    @Lob
    @Column(name = "notification_data", columnDefinition = "TEXT")
    private Map<String, Object> notificationData;
    
    /**
     * 액션 필요 여부
     * true이면 사용자 액션(승인/거부) 필요
     */
    @Column(name = "action_required", nullable = false)
    @Builder.Default
    private Boolean actionRequired = false;
    
    /**
     * 액션 URL
     * 승인/거부를 처리할 엔드포인트
     */
    @Column(name = "action_url", length = 500)
    private String actionUrl;
    
    /**
     * 그룹 ID
     * 관련된 알림들을 그룹화
     */
    @Column(name = "group_id", length = 100)
    private String groupId;
    
    /**
     * 생성 시간
     */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    /**
     * 수정 시간
     */
    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
    
    /**
     * 알림을 읽음으로 표시
     * 
     * @param userId 읽은 사용자 ID
     */
    public void markAsRead(String userId) {
        this.isRead = true;
        this.readAt = LocalDateTime.now();
        this.readBy = userId;
    }
    
    /**
     * 알림이 만료되었는지 확인
     *
     * @return 만료되었으면 true
     */
    @JsonIgnore
    public boolean isExpired() {
        return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * 높은 우선순위인지 확인
     *
     * @return CRITICAL 또는 HIGH이면 true
     */
    @JsonIgnore
    public boolean isHighPriority() {
        return "CRITICAL".equals(priority) || "HIGH".equals(priority);
    }
    
    /**
     * 알림 유형 enum
     */
    public enum NotificationType {
        APPROVAL_REQUEST("승인 요청"),
        APPROVAL_GRANTED("승인됨"),
        APPROVAL_REJECTED("거부됨"),
        APPROVAL_TIMEOUT("타임아웃"),
        TOOL_EXECUTED("도구 실행됨"),
        TOOL_FAILED("도구 실행 실패");
        
        private final String description;
        
        NotificationType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
}