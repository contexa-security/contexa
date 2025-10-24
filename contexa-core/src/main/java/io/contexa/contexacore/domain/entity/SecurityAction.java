package io.contexa.contexacore.domain.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.contexa.contexacommon.annotation.SoarTool;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 보안 액션 도메인 엔티티
 * 
 * 보안 인시던트에 대한 대응 액션을 표현합니다.
 * MCP 도구 실행, 승인 상태, 실행 결과를 관리합니다.
 */
@Entity
@Table(name = "security_actions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityAction {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "action_id")
    private String actionId;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "incident_id")
    private SecurityIncident incident;
    
    @Column(name = "action_type", nullable = false)
    private String actionType;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "action_status", nullable = false)
    @Builder.Default
    private ActionStatus status = ActionStatus.PENDING;
    
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", nullable = false)
    @Builder.Default
    private SoarTool.RiskLevel riskLevel = SoarTool.RiskLevel.MEDIUM;
    
    @ElementCollection
    @CollectionTable(name = "action_parameters", 
                     joinColumns = @JoinColumn(name = "action_id"))
    @MapKeyColumn(name = "param_key")
    @Column(name = "param_value", columnDefinition = "TEXT")
    @Builder.Default
    private Map<String, String> parameters = new HashMap<>();
    
    @Column(name = "requires_approval")
    @Builder.Default
    private Boolean requiresApproval = false;
    
    @Column(name = "approval_request_id")
    private String approvalRequestId;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "approval_status")
    private ApprovalStatus approvalStatus;
    
    @Column(name = "approved_by")
    private String approvedBy;
    
    @Column(name = "approval_comment")
    private String approvalComment;
    
    @Column(name = "approved_at")
    private LocalDateTime approvedAt;
    
    @Column(name = "auto_approved")
    @Builder.Default
    private Boolean autoApproved = false;
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @Column(name = "scheduled_at")
    private LocalDateTime scheduledAt;
    
    @Column(name = "started_at")
    private LocalDateTime startedAt;
    
    @Column(name = "completed_at")
    private LocalDateTime completedAt;
    
    @Column(name = "failed_at")
    private LocalDateTime failedAt;
    
    @Column(name = "execution_duration_ms")
    private Long executionDurationMs;
    
    @Column(name = "result", columnDefinition = "TEXT")
    private String result;
    
    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;
    
    @Column(name = "retry_count")
    @Builder.Default
    private Integer retryCount = 0;
    
    @Column(name = "max_retries")
    @Builder.Default
    private Integer maxRetries = 3;
    
    @Column(name = "is_compensatable")
    @Builder.Default
    private Boolean isCompensatable = false;
    
    @Column(name = "compensation_action_id")
    private String compensationActionId;
    
    @Column(name = "compensation_executed")
    @Builder.Default
    private Boolean compensationExecuted = false;
    
    @Column(name = "compensation_executed_at")
    private LocalDateTime compensationExecutedAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
    
    @Column(name = "last_retry_at")
    private LocalDateTime lastRetryAt;
    
    @Column(name = "priority")
    @Builder.Default
    private Integer priority = 3;
    
    @Column(name = "auto_execute")
    @Builder.Default
    private Boolean autoExecute = false;
    
    @Column(name = "parent_action_id")
    private String parentActionId;
    
    @Column(name = "execution_order")
    @Builder.Default
    private Integer executionOrder = 0;
    
    @Column(name = "rollbackable")
    @Builder.Default
    private Boolean rollbackable = false;
    
    @Column(name = "approver_id")
    private String approverId;
    
    @Column(name = "executed_at")
    private LocalDateTime executedAt;
    
    @Column(name = "execution_result")
    private String executionResult;
    
    @Column(name = "execution_output", columnDefinition = "TEXT")
    private String executionOutput;
    
    @Column(name = "execution_duration")
    private Long executionDuration;
    
    @ElementCollection
    @CollectionTable(name = "action_audit_log", 
                     joinColumns = @JoinColumn(name = "action_id"))
    @Column(name = "log_entry")
    @Builder.Default
    private List<String> auditLog = new ArrayList<>();
    
    /**
     * 액션 타입
     */
    public enum ActionType {
        // 네트워크 관련
        BLOCK_NETWORK("네트워크 차단"),
        ISOLATE_HOST("호스트 격리"),
        BLOCK_IP("IP 차단"),
        BLOCK_DOMAIN("도메인 차단"),
        
        // 프로세스 관련
        KILL_PROCESS("프로세스 종료"),
        QUARANTINE_FILE("파일 격리"),
        DELETE_FILE("파일 삭제"),
        
        // 사용자 관련
        DISABLE_USER("사용자 비활성화"),
        RESET_PASSWORD("비밀번호 재설정"),
        REVOKE_ACCESS("접근 권한 철회"),
        
        // 시스템 관련
        PATCH_SYSTEM("시스템 패치"),
        RESTART_SERVICE("서비스 재시작"),
        UPDATE_CONFIGURATION("설정 업데이트"),
        
        // 조사 관련
        COLLECT_LOGS("로그 수집"),
        CAPTURE_MEMORY("메모리 캡처"),
        FORENSIC_ANALYSIS("포렌식 분석"),
        
        // 알림 관련
        SEND_ALERT("알림 발송"),
        ESCALATE_INCIDENT("인시던트 에스컬레이션"),
        CREATE_TICKET("티켓 생성");
        
        private final String description;
        
        ActionType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
        
        public boolean isDestructive() {
            return this == DELETE_FILE || this == KILL_PROCESS;
        }
        
        public boolean isReversible() {
            return this != DELETE_FILE && this != FORENSIC_ANALYSIS;
        }
    }
    
    /**
     * 액션 상태
     */
    public enum ActionStatus {
        PENDING("대기중"),
        AWAITING_APPROVAL("승인 대기"),
        APPROVED("승인됨"),
        REJECTED("거부됨"),
        SCHEDULED("예약됨"),
        IN_PROGRESS("실행중"),
        COMPLETED("완료"),
        FAILED("실패"),
        CANCELLED("취소됨"),
        COMPENSATED("보상됨"),
        EXECUTING("실행중"),
        UNDONE("실행취소");
        
        private final String description;
        
        ActionStatus(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
        
        public boolean isTerminal() {
            return this == COMPLETED || this == FAILED || 
                   this == CANCELLED || this == REJECTED;
        }
        
        public boolean canRetry() {
            return this == FAILED;
        }
    }
    
    /**
     * 승인 상태
     */
    public enum ApprovalStatus {
        NOT_REQUIRED("승인 불필요"),
        PENDING("승인 대기"),
        APPROVED("승인됨"),
        DENIED("거부됨"),
        TIMEOUT("시간 초과"),
        AUTO_APPROVED("자동 승인"),
        AUTO_DENIED("자동 거부");
        
        private final String description;
        
        ApprovalStatus(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 파라미터 추가
     */
    public void addParameter(String key, String value) {
        if (parameters == null) {
            parameters = new HashMap<>();
        }
        parameters.put(key, value);
    }
    
    /**
     * 감사 로그 추가
     */
    public void addAuditLog(String entry) {
        if (auditLog == null) {
            auditLog = new ArrayList<>();
        }
        auditLog.add(String.format("[%s] %s", LocalDateTime.now(), entry));
    }
    
    /**
     * 액션 시작
     */
    public void start() {
        this.status = ActionStatus.IN_PROGRESS;
        this.startedAt = LocalDateTime.now();
        addAuditLog("Action started");
    }
    
    /**
     * 액션 완료
     */
    public void complete(String result) {
        this.status = ActionStatus.COMPLETED;
        this.completedAt = LocalDateTime.now();
        this.result = result;
        if (startedAt != null) {
            this.executionDurationMs = 
                java.time.Duration.between(startedAt, completedAt).toMillis();
        }
        addAuditLog("Action completed: " + result);
    }
    
    /**
     * 액션 실패
     */
    public void fail(String errorMessage) {
        this.status = ActionStatus.FAILED;
        this.failedAt = LocalDateTime.now();
        this.errorMessage = errorMessage;
        if (startedAt != null) {
            this.executionDurationMs = 
                java.time.Duration.between(startedAt, failedAt).toMillis();
        }
        addAuditLog("Action failed: " + errorMessage);
    }
    
    /**
     * 승인 처리
     */
    public void approve(String approver, String comment) {
        this.approvalStatus = ApprovalStatus.APPROVED;
        this.approvedBy = approver;
        this.approvalComment = comment;
        this.approvedAt = LocalDateTime.now();
        this.status = ActionStatus.APPROVED;
        addAuditLog("Approved by " + approver + ": " + comment);
    }
    
    /**
     * 거부 처리
     */
    public void deny(String denier, String reason) {
        this.approvalStatus = ApprovalStatus.DENIED;
        this.approvedBy = denier;
        this.approvalComment = reason;
        this.approvedAt = LocalDateTime.now();
        this.status = ActionStatus.REJECTED;
        addAuditLog("Denied by " + denier + ": " + reason);
    }
    
    /**
     * 재시도 가능 여부
     */
    @JsonIgnore
    public boolean canRetry() {
        return status.canRetry() && retryCount < maxRetries;
    }

    /**
     * 재시도 증가
     */
    public void incrementRetry() {
        this.retryCount++;
        addAuditLog("Retry attempt " + retryCount + " of " + maxRetries);
    }

    /**
     * 보상 가능 여부
     */
    @JsonIgnore
    public boolean canCompensate() {
        return isCompensatable && status == ActionStatus.COMPLETED;
    }

    /**
     * 실행 준비 여부
     */
    @JsonIgnore
    public boolean isReadyToExecute() {
        if (requiresApproval) {
            return approvalStatus == ApprovalStatus.APPROVED ||
                   approvalStatus == ApprovalStatus.AUTO_APPROVED;
        }
        return status == ActionStatus.PENDING || status == ActionStatus.SCHEDULED;
    }

    /**
     * 고위험 액션 여부
     */
    @JsonIgnore
    public boolean isHighRisk() {
        // ActionType enum을 사용하여 actionType 문자열을 체크
        try {
            ActionType type = ActionType.valueOf(actionType);
            return riskLevel == SoarTool.RiskLevel.HIGH || 
                   riskLevel == SoarTool.RiskLevel.CRITICAL ||
                   type.isDestructive();
        } catch (Exception e) {
            // actionType이 enum과 매치되지 않으면 risk level만 체크
            return riskLevel == SoarTool.RiskLevel.HIGH || 
                   riskLevel == SoarTool.RiskLevel.CRITICAL;
        }
    }
    
}