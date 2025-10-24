package io.contexa.contexacore.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

/**
 * SOAR 승인 요청
 * 
 * 위험한 작업에 대한 승인 요청 정보를 캡슐화합니다.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApprovalRequest implements Serializable {
    
    private String requestId;
    private String sessionId;
    private String incidentId;
    private String toolName;
    private String actionType;
    private Map<String, Object> parameters;
    private String reason;
    private RiskLevel riskLevel;
    private ApprovalType approvalType;
    private ApprovalStatus status;
    private LocalDateTime requestedAt;
    private String requestedBy;
    private LocalDateTime approvedAt;
    private String approvedBy;
    private String rejectionReason;
    private Set<String> requiredRoles;
    private Integer requiredApprovers;
    private Integer approvalTimeout;
    private String potentialImpact;
    private Map<String, Object> metadata;
    
    // 추가 필드
    private Long id;
    private boolean approved;
    private String organizationId;
    private String actionDescription;
    private String toolDescription;
    private Map<String, Object> context;
    private String toolType;
    private String arguments;
    private String approverId;
    private String userId;
    private String requesterEmail;
    private String requesterPhone;
    private String approver;
    private java.time.Instant approvalTime;
    
    /**
     * UnifiedNotificationService에서 사용하는 메서드
     */
    public String getRequesterEmail() {
        if (requesterEmail != null) {
            return requesterEmail;
        }
        // metadata에서 가져오기 시도
        if (metadata != null && metadata.containsKey("email")) {
            return (String) metadata.get("email");
        }
        return null;
    }
    
    public String getRequesterPhone() {
        if (requesterPhone != null) {
            return requesterPhone;
        }
        // metadata에서 가져오기 시도
        if (metadata != null && metadata.containsKey("phone")) {
            return (String) metadata.get("phone");
        }
        return null;
    }
    
    /**
     * 위험 수준
     */
    public enum RiskLevel {
        CRITICAL("치명적", 9),
        HIGH("높음", 7),
        MEDIUM("중간", 5),
        LOW("낮음", 3),
        INFO("정보", 1);
        
        private final String description;
        private final int score;
        
        RiskLevel(String description, int score) {
            this.description = description;
            this.score = score;
        }
        
        public String getDescription() {
            return description;
        }
        
        public int getScore() {
            return score;
        }
    }
    
    /**
     * 승인 유형
     */
    public enum ApprovalType {
        AUTO("자동 승인"),
        MANUAL("수동 승인 필요"),
        SINGLE("단일 승인"),
        MULTI("다중 승인 필요"),
        UNANIMOUS("만장일치"),
        EMERGENCY("긴급 승인");
        
        private final String description;
        
        ApprovalType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 승인 상태
     */
    public enum ApprovalStatus {
        PENDING("대기 중"),
        APPROVED("승인됨"),
        REJECTED("거부됨"),
        EXPIRED("만료됨"),
        CANCELLED("취소됨");
        
        private final String description;
        
        ApprovalStatus(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 승인 요청 생성
     */
    public static ApprovalRequest create(String sessionId, String toolName, Map<String, Object> parameters, String reason) {
        ApprovalRequest request = new ApprovalRequest();
        request.requestId = "APR-" + System.currentTimeMillis();
        request.sessionId = sessionId;
        request.toolName = toolName;
        request.parameters = parameters;
        request.reason = reason;
        request.status = ApprovalStatus.PENDING;
        request.requestedAt = LocalDateTime.now();
        return request;
    }
    
    /**
     * 승인 처리
     */
    public void approve(String approver) {
        this.status = ApprovalStatus.APPROVED;
        this.approvedBy = approver;
        this.approvedAt = LocalDateTime.now();
    }
    
    /**
     * 거부 처리
     */
    public void reject(String approver, String reason) {
        this.status = ApprovalStatus.REJECTED;
        this.approvedBy = approver;
        this.approvedAt = LocalDateTime.now();
        this.rejectionReason = reason;
    }
    
    /**
     * 만료 처리
     */
    public void expire() {
        this.status = ApprovalStatus.EXPIRED;
    }
    
    /**
     * 취소 처리
     */
    public void cancel() {
        this.status = ApprovalStatus.CANCELLED;
    }
    
    /**
     * 자동 승인 가능 여부
     */
    @JsonIgnore
    public boolean isAutoApprovable() {
        return this.riskLevel != null &&
               (this.riskLevel == RiskLevel.LOW || this.riskLevel == RiskLevel.INFO);
    }
    
    public Integer getTimeoutMinutes() {
        return this.approvalTimeout;
    }
    
    // 빌더 패턴을 위한 정적 메서드
    public static ApprovalRequestBuilder builder() {
        return new ApprovalRequestBuilder();
    }
    
    // 승인 추가 메서드
    public void addApproval(String approver, String approverName, String approverRole, String comments) {
        this.status = ApprovalStatus.APPROVED;
        this.approvedBy = approver;
        this.approvedAt = LocalDateTime.now();
        // 실제로는 별도의 승인 기록을 관리해야 함
    }
    
    // 빌더 클래스
    public static class ApprovalRequestBuilder {
        private ApprovalRequest request = new ApprovalRequest();
        
        public ApprovalRequestBuilder requestId(String requestId) {
            request.requestId = requestId;
            return this;
        }
        
        public ApprovalRequestBuilder sessionId(String sessionId) {
            request.sessionId = sessionId;
            return this;
        }
        
        public ApprovalRequestBuilder incidentId(String incidentId) {
            request.incidentId = incidentId;
            return this;
        }
        
        public ApprovalRequestBuilder toolName(String toolName) {
            request.toolName = toolName;
            return this;
        }
        
        public ApprovalRequestBuilder toolDescription(String description) {
            // toolDescription 필드가 없으므로 metadata에 저장
            if (request.metadata == null) {
                request.metadata = new java.util.HashMap<>();
            }
            request.metadata.put("toolDescription", description);
            return this;
        }
        
        public ApprovalRequestBuilder riskLevel(RiskLevel riskLevel) {
            request.riskLevel = riskLevel;
            return this;
        }
        
        public ApprovalRequestBuilder actionDescription(String actionDescription) {
            request.actionDescription = actionDescription;
            return this;
        }
        
        public ApprovalRequestBuilder toolParameters(Map<String, Object> toolParameters) {
            request.parameters = new java.util.HashMap<>(toolParameters);
            return this;
        }
        
        public ApprovalRequestBuilder status(ApprovalStatus status) {
            request.status = status;
            return this;
        }
        
        public ApprovalRequestBuilder approvalType(ApprovalType approvalType) {
            request.approvalType = approvalType;
            return this;
        }
        
        public ApprovalRequestBuilder requestedBy(String requestedBy) {
            request.requestedBy = requestedBy;
            return this;
        }
        
        public ApprovalRequestBuilder requestReason(String reason) {
            request.reason = reason;
            return this;
        }
        
        public ApprovalRequestBuilder riskAssessment(String assessment) {
            if (request.metadata == null) {
                request.metadata = new java.util.HashMap<>();
            }
            request.metadata.put("riskAssessment", assessment);
            return this;
        }
        
        public ApprovalRequestBuilder potentialImpact(String potentialImpact) {
            request.potentialImpact = potentialImpact;
            return this;
        }
        
        public ApprovalRequestBuilder timeoutMinutes(Integer timeoutMinutes) {
            request.approvalTimeout = timeoutMinutes;
            return this;
        }
        
        public ApprovalRequestBuilder organizationId(String organizationId) {
            request.organizationId = organizationId;
            return this;
        }
        
        public ApprovalRequest build() {
            request.requestedAt = LocalDateTime.now();
            if (request.requiredRoles == null) {
                request.requiredRoles = new java.util.HashSet<>();
            }
            return request;
        }
    }
}