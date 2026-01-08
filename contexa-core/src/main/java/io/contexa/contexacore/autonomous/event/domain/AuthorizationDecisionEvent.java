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

/**
 * 인가 결정 이벤트 도메인 모델
 * 
 * AINative IAM의 모든 인가 결정을 이벤트로 발행하기 위한 모델입니다.
 * 이를 통해 SecurityPlaneAgent가 실시간으로 모든 접근 시도를 분석할 수 있습니다.
 */
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

    // AI Native v3.1: Zero Trust 세션 컨텍스트 필드
    // HCADContext에서 추출한 세션/요청 패턴 정보
    // LLM 프롬프트에서 NOT_PROVIDED 방지를 위해 추가
    @JsonProperty("is_new_session")
    private Boolean isNewSession;

    @JsonProperty("is_new_user")
    private Boolean isNewUser;

    @JsonProperty("is_new_device")
    private Boolean isNewDevice;

    @JsonProperty("recent_request_count")
    private Integer recentRequestCount;

    /**
     * 인가 결과 열거형
     */
    public enum AuthorizationResult {
        ALLOWED,
        DENIED,
        CONDITIONAL,
        PENDING_APPROVAL,
        ERROR
    }
    
    /**
     * AI 평가 정보
     */
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
    
    /**
     * 빌더를 통한 이벤트 생성 시 자동으로 ID와 타임스탬프 설정
     */
    public static class AuthorizationDecisionEventBuilder {
        public AuthorizationDecisionEventBuilder() {
            this.eventId = UUID.randomUUID().toString();
            this.timestamp = Instant.now();
        }
    }
    
    // 호환성을 위한 추가 메서드들 (별칭)
    // Jackson 역직렬화 시 setter 없는 getter가 null 반환하면 오류 발생하므로 @JsonIgnore 추가
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