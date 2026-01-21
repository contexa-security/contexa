package io.contexa.contexacoreenterprise.soar.notification;

import lombok.Data;
import lombok.Builder;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
public class ApprovalNotification {
    
    private String approvalId;
    private String toolName;
    private String description;
    private String incidentId;
    private String organizationId;
    private String riskLevel;
    private Map<String, Object> toolArguments;
    private Instant requestedAt;
    private String requestedBy;
    private long timeoutSeconds;
    private Map<String, Object> metadata;
}