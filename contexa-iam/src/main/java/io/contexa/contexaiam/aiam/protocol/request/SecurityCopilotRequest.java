package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexaiam.aiam.protocol.context.SecurityCopilotContext;
import io.contexa.contexacommon.domain.request.IAMRequest;
import lombok.*;

import java.util.Map;

@Getter
@Setter
public class SecurityCopilotRequest extends IAMRequest<SecurityCopilotContext> {

    private String securityQuery;
    private String analysisScope;
    private String userId;
    private String organizationId;
    private String analysisType;
    private boolean enableThreatHunting;
    private boolean enableComplianceCheck;
    private boolean enableVulnerabilityAssessment;
    private Map<String, Object> metadata;

    public SecurityCopilotRequest() {
        this(null, null);
    }

    public SecurityCopilotRequest(SecurityCopilotContext context, String operation) {
        super(context, operation);
    }

    public String getRequestId() {
        if (metadata != null && metadata.containsKey("requestId")) {
            return (String) metadata.get("requestId");
        }
        return "security-req-" + System.currentTimeMillis();
    }
} 