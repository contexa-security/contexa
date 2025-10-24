package io.contexa.contexacore.domain;

import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;
import java.util.HashMap;

/**
 * SOAR (Security Orchestration, Automation and Response) 요청 객체.
 * AI 기반 SOAR 분석을 위한 입력 데이터를 캡슐화합니다.
 */
@Getter
@Setter
public class SoarRequest extends AIRequest<SoarContext> {

    private String incidentId;
    private String threatType;
    private String description;
    private String initialQuery;
    private String approvalId;
    private Map<String, Object> metadata;

    // Builder 패턴을 위한 생성자들
    public SoarRequest(SoarContext context, String operation, String organizationId, 
                       String incidentId, String threatType, String description, 
                       String initialQuery, String approvalId, Map<String, Object> metadata) {
        super(context, operation, organizationId);
        this.incidentId = incidentId;
        this.threatType = threatType;
        this.description = description;
        this.initialQuery = initialQuery;
        this.approvalId = approvalId;
        this.metadata = metadata != null ? metadata : new HashMap<>();
    }

    // 새로운 생성자: initialQuery를 받는 생성자 추가  
    public SoarRequest(SoarContext context, String operation) {
        super(context != null ? context : new SoarContext(), operation, "default-org");
    }

    public SoarRequest(SoarContext context, String operation, String initialQuery) {
        super(context, operation, "default-org");
        this.initialQuery = initialQuery;
    }

    public String getIncidentId() {
        if (metadata != null && metadata.containsKey("incidentId")) {
            return (String) metadata.get("incidentId");
        }
        return "soar-inc-" + System.currentTimeMillis();
    }
    
    // 명시적 getter 오버라이드 (Lombok 문제 해결)
    @Override
    public SoarContext getContext() {
        return super.getContext();
    }
    
    // 누락된 메서드들 추가
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
    
    // 추가 setter 메서드들
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
        // context에는 userId setter가 없으므로 metadata에 저장
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
    
    /**
     * Builder 패턴을 위한 정적 빌더 클래스
     */
    public static class SoarRequestBuilder {
        private SoarContext context;
        private String operation;
        private String organizationId = "default-org";
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
        
        public SoarRequestBuilder operation(String operation) {
            this.operation = operation;
            return this;
        }
        
        public SoarRequestBuilder organizationId(String organizationId) {
            this.organizationId = organizationId;
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
            // sessionId와 userId를 context와 metadata에 설정
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
            
            return new SoarRequest(context, operation, organizationId, 
                                   incidentId, threatType, description, 
                                   initialQuery, approvalId, metadata);
        }
    }
    
    /**
     * Builder 패턴을 위한 정적 팩토리 메서드
     */
    public static SoarRequestBuilder builder() {
        return new SoarRequestBuilder();
    }
}