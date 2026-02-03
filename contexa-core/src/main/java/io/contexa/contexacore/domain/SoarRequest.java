package io.contexa.contexacore.domain;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;
import java.util.HashMap;

@Getter
@Setter
public class SoarRequest extends AIRequest<SoarContext> {

    private String incidentId;
    private String threatType;
    private String description;
    private String initialQuery;
    private String approvalId;
    private Map<String, Object> metadata;

    public SoarRequest(SoarContext context, TemplateType templateType, DiagnosisType diagnosisType,
                       String incidentId, String threatType, String description,
                       String initialQuery, String approvalId, Map<String, Object> metadata) {
        super(context, templateType, diagnosisType);
        this.incidentId = incidentId;
        this.threatType = threatType;
        this.description = description;
        this.initialQuery = initialQuery;
        this.approvalId = approvalId;
        this.metadata = metadata != null ? metadata : new HashMap<>();
    }

    public SoarRequest(SoarContext context, TemplateType templateType, DiagnosisType diagnosisType) {
        super(context, templateType, diagnosisType);
    }

    public String getIncidentId() {
        if (metadata != null && metadata.containsKey("incidentId")) {
            return (String) metadata.get("incidentId");
        }
        return "soar-inc-" + System.currentTimeMillis();
    }

    @Override
    public SoarContext getContext() {
        return super.getContext();
    }

    public String getSessionId() {
        if (getContext() != null) {
            return getContext().getSessionId();
        }
        return null;
    }
    
    public String getUserId() {
        if (getContext() != null) {
            return getContext().getUserId();
        }
        return null;
    }
    
    public String getQuery() {
        return this.initialQuery;
    }

    public void setQuery(String query) {
        this.initialQuery = query;
    }
    
    public void setSessionId(String sessionId) {
        if (getContext() != null) {
            getContext().setSessionId(sessionId);
        }
    }
    
    public void setOrganizationId(String organizationId) {
        if (getContext() != null) {
            getContext().setOrganizationId(organizationId);
        }
    }
    
    public void setUserId(String userId) {
        
        if (metadata == null) {
            metadata = new HashMap<>();
        }
        metadata.put("userId", userId);
    }
    
    public void setThreatLevel(SoarContext.ThreatLevel threatLevel) {
        if (getContext() != null) {
            getContext().setThreatLevel(threatLevel);
        }
    }
    
    public void setQueryIntent(String queryIntent) {
        if (getContext() != null) {
            getContext().setQueryIntent(queryIntent);
        }
    }
    
    public void setExtractedEntities(Map<String, Object> entities) {
        if (getContext() != null) {
            getContext().getExtractedEntities().putAll(entities);
        }
    }
    
    public void setConversationHistory(java.util.List<io.contexa.contexacore.domain.Message> history) {
        if (getContext() != null) {
            getContext().setConversationHistory(history);
        }
    }
    
    public void setApprovedTools(java.util.Set<String> approvedTools) {
        if (getContext() != null) {
            getContext().getApprovedTools().addAll(approvedTools);
        }
    }
    
    public void setRequiresApproval(boolean requiresApproval) {
        if (getContext() != null) {
            getContext().setRequiresApproval(requiresApproval);
        }
    }
    
    public void setEmergencyMode(boolean emergencyMode) {
        if (getContext() != null) {
            getContext().setEmergencyMode(emergencyMode);
        }
    }
    
    public void setTimestamp(java.time.LocalDateTime timestamp) {
        if (metadata == null) {
            metadata = new HashMap<>();
        }
        metadata.put("timestamp", timestamp);
    }

    public static class SoarRequestBuilder {
        private SoarContext context;
        private TemplateType templateType;
        private DiagnosisType diagnosisType;
        private String incidentId;
        private String threatType;
        private String description;
        private String initialQuery;
        private String approvalId;
        private String sessionId;
        private String userId;
        private Map<String, Object> metadata = new HashMap<>();
        
        public SoarRequestBuilder context(SoarContext context) {
            this.context = context;
            return this;
        }
        
        public SoarRequestBuilder templateType(TemplateType templateType) {
            this.templateType = templateType;
            return this;
        }
        
        public SoarRequestBuilder diagnosisType(DiagnosisType diagnosisType) {
            this.diagnosisType = diagnosisType;
            return this;
        }
        
        public SoarRequestBuilder incidentId(String incidentId) {
            this.incidentId = incidentId;
            return this;
        }
        
        public SoarRequestBuilder threatType(String threatType) {
            this.threatType = threatType;
            return this;
        }
        
        public SoarRequestBuilder description(String description) {
            this.description = description;
            return this;
        }
        
        public SoarRequestBuilder initialQuery(String initialQuery) {
            this.initialQuery = initialQuery;
            return this;
        }
        
        public SoarRequestBuilder approvalId(String approvalId) {
            this.approvalId = approvalId;
            return this;
        }
        
        public SoarRequestBuilder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }
        
        public SoarRequestBuilder userId(String userId) {
            this.userId = userId;
            return this;
        }
        
        public SoarRequestBuilder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }
        
        public SoarRequest build() {
            
            if (context == null) {
                context = new SoarContext();
            }
            if (sessionId != null) {
                context.setSessionId(sessionId);
            }
            if (userId != null) {
                context.setUserId(userId);
                metadata.put("userId", userId);
            }
            
            return new SoarRequest(context, templateType, diagnosisType,
                                   incidentId, threatType, description, 
                                   initialQuery, approvalId, metadata);
        }
    }

    public static SoarRequestBuilder builder() {
        return new SoarRequestBuilder();
    }
}