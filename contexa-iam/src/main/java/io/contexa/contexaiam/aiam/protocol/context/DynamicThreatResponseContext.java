package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.domain.context.IAMContext;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Data
@EqualsAndHashCode(callSuper = true)
public class DynamicThreatResponseContext extends IAMContext {

    private ThreatInfo threatInfo;

    private ResponseInfo responseInfo;

    private PolicyGenerationHint hint;

    private Map<String, Object> additionalContext;

    private String eventId;

    private LocalDateTime createdAt;
    
    public DynamicThreatResponseContext() {
        super("system", "dynamic-threat-session-" + System.currentTimeMillis(), 
              SecurityLevel.MAXIMUM, AuditRequirement.REQUIRED);
        this.additionalContext = new HashMap<>();
        this.createdAt = LocalDateTime.now();
    }
    
    public DynamicThreatResponseContext(String userId, String sessionId) {
        super(userId, sessionId, SecurityLevel.MAXIMUM, AuditRequirement.REQUIRED);
        this.additionalContext = new HashMap<>();
        this.createdAt = LocalDateTime.now();
    }

    @Data
    public static class ThreatInfo {
        private String threatType;
        private String attackVector;
        private String targetResource;
        private String attackerIdentity;
        private String severity;
        private LocalDateTime occurredAt;
        private Map<String, Object> additionalInfo;
        
        public ThreatInfo() {
            this.additionalInfo = new HashMap<>();
        }
    }

    @Data
    public static class ResponseInfo {
        private String mitigationAction;
        private boolean successful;
        private String description;
        private Long incidentId;
        private String soarWorkflowId;
        private Map<String, Object> additionalInfo;
        
        public ResponseInfo() {
            this.additionalInfo = new HashMap<>();
        }
    }

    @Data
    public static class PolicyGenerationHint {
        private String preferredPolicyType;  
        private String scope;                 
        private Integer priority;              
        private Boolean requiresApproval;      
        private String targetAudience;         
    }

    public DynamicThreatResponseContext withThreatInfo(ThreatInfo threatInfo) {
        this.threatInfo = threatInfo;
        return this;
    }
    
    public DynamicThreatResponseContext withResponseInfo(ResponseInfo responseInfo) {
        this.responseInfo = responseInfo;
        return this;
    }
    
    public DynamicThreatResponseContext withHint(PolicyGenerationHint hint) {
        this.hint = hint;
        return this;
    }
    
    public DynamicThreatResponseContext withEventId(String eventId) {
        this.eventId = eventId;
        return this;
    }
    
    public DynamicThreatResponseContext withAdditionalContext(String key, Object value) {
        if (this.additionalContext == null) {
            this.additionalContext = new HashMap<>();
        }
        this.additionalContext.put(key, value);
        return this;
    }

    public void adjustSecurityLevelBySeverity() {

    }
    
    @Override
    public String getIAMContextType() {
        return "DYNAMIC_THREAT_RESPONSE";
    }
    
    @Override
    public String toString() {
        return String.format("DynamicThreatResponseContext{eventId='%s', threatType='%s', severity='%s', targetResource='%s'}",
                eventId, 
                threatInfo != null ? threatInfo.getThreatType() : "null",
                threatInfo != null ? threatInfo.getSeverity() : "null",
                threatInfo != null ? threatInfo.getTargetResource() : "null");
    }
}