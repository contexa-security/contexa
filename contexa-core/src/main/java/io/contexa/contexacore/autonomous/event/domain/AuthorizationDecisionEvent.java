package io.contexa.contexacore.autonomous.event.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationDecisionEvent {
    
    @JsonProperty("event_id")
    private String eventId;
    
    @JsonProperty("event_type")
    @Builder.Default
    private String eventType = "AUTHORIZATION_DECISION";
    
    @JsonProperty("timestamp")
    private Instant timestamp;
    
    @JsonProperty("principal")
    private String principal;
    
    @JsonProperty("user_id")
    private String userId;
    
    @JsonProperty("organization_id")
    private String organizationId;
    
    @JsonProperty("resource")
    private String resource;
    
    @JsonProperty("action")
    private String action;
    
    @JsonProperty("http_method")
    private String httpMethod;
    
    @JsonProperty("result")
    private AuthorizationResult result;
    
    @JsonProperty("reason")
    private String reason;
    
    @JsonProperty("client_ip")
    private String clientIp;
    
    @JsonProperty("user_agent")
    private String userAgent;
    
    @JsonProperty("session_id")
    private String sessionId;
    
    @JsonProperty("request_id")
    private String requestId;
    
    @JsonProperty("ai_assessment")
    private AIAssessment aiAssessment;
    
    @JsonProperty("risk_score")
    private Double riskScore;
    
    @JsonProperty("trust_score")
    private Double trustScore;

    @JsonProperty("metadata")
    private Map<String, Object> metadata;

    
    
    
    @JsonProperty("is_new_session")
    private Boolean isNewSession;

    @JsonProperty("is_new_user")
    private Boolean isNewUser;

    @JsonProperty("is_new_device")
    private Boolean isNewDevice;

    @JsonProperty("recent_request_count")
    private Integer recentRequestCount;

    
    public enum AuthorizationResult {
        ALLOWED,
        DENIED,
        CONDITIONAL,
        PENDING_APPROVAL,
        ERROR
    }
    
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class AIAssessment {
        @JsonProperty("trust_score")
        private Double trustScore;
        
        @JsonProperty("risk_tags")
        private String[] riskTags;
        
        @JsonProperty("anomaly_detected")
        private Boolean anomalyDetected;
        
        @JsonProperty("behavior_pattern")
        private String behaviorPattern;
        
        @JsonProperty("recommendation")
        private String recommendation;
        
        @JsonProperty("confidence")
        private Double confidence;
    }
    
    
    public static class AuthorizationDecisionEventBuilder {
        public AuthorizationDecisionEventBuilder() {
            this.eventId = UUID.randomUUID().toString();
            this.timestamp = Instant.now();
        }
    }
    
    
    
    @JsonIgnore
    public String getIpAddress() {
        return clientIp;
    }

    @JsonIgnore
    public String getSourceIp() {
        return clientIp;
    }

    @JsonIgnore
    public Map<String, Object> getAdditionalContext() {
        return metadata;
    }
    
    public boolean isGranted() {
        return result == AuthorizationResult.ALLOWED;
    }
}