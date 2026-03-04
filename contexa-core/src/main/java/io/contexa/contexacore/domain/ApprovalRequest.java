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

    public String getRequesterEmail() {
        if (requesterEmail != null) {
            return requesterEmail;
        }
        
        if (metadata != null && metadata.containsKey("email")) {
            return (String) metadata.get("email");
        }
        return null;
    }
    
    public String getRequesterPhone() {
        if (requesterPhone != null) {
            return requesterPhone;
        }
        
        if (metadata != null && metadata.containsKey("phone")) {
            return (String) metadata.get("phone");
        }
        return null;
    }

    public enum ApprovalType {
        AUTO("Auto Approval"),
        MANUAL("Manual Approval Required"),
        SINGLE("Single Approval"),
        MULTI("Multi Approval Required"),
        UNANIMOUS("Unanimous"),
        EMERGENCY("Emergency Approval");
        
        private final String description;
        
        ApprovalType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }

    public enum ApprovalStatus {
        PENDING("Pending"),
        APPROVED("Approved"),
        REJECTED("Rejected"),
        EXPIRED("Expired"),
        CANCELLED("Cancelled");
        
        private final String description;
        
        ApprovalStatus(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }

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

    public void approve(String approver) {
        this.status = ApprovalStatus.APPROVED;
        this.approvedBy = approver;
        this.approvedAt = LocalDateTime.now();
    }

    public void reject(String approver, String reason) {
        this.status = ApprovalStatus.REJECTED;
        this.approvedBy = approver;
        this.approvedAt = LocalDateTime.now();
        this.rejectionReason = reason;
    }

    public void expire() {
        this.status = ApprovalStatus.EXPIRED;
    }

    public void cancel() {
        this.status = ApprovalStatus.CANCELLED;
    }

    @JsonIgnore
    public boolean isAutoApprovable() {
        return this.approvalType != null && this.approvalType == ApprovalType.AUTO;
    }
    
    public Integer getTimeoutMinutes() {
        return this.approvalTimeout;
    }

    public static ApprovalRequestBuilder builder() {
        return new ApprovalRequestBuilder();
    }

    public void addApproval(String approver, String approverName, String approverRole, String comments) {
        this.status = ApprovalStatus.APPROVED;
        this.approvedBy = approver;
        this.approvedAt = LocalDateTime.now();
        
    }

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
            
            if (request.metadata == null) {
                request.metadata = new java.util.HashMap<>();
            }
            request.metadata.put("toolDescription", description);
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