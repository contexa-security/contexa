package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.domain.context.IAMContext;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * 동적 위협 대응을 위한 도메인 컨텍스트
 * 
 * AI 기반 동적 위협 대응 합성 Lab에서 사용하는 컨텍스트 정보를 담습니다.
 * 위협 정보, 대응 정보, 정책 생성 힌트 등을 포함합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class DynamicThreatResponseContext extends IAMContext {
    
    /**
     * 위협 정보
     */
    private ThreatInfo threatInfo;
    
    /**
     * 대응 정보
     */
    private ResponseInfo responseInfo;
    
    /**
     * 정책 생성 힌트
     */
    private PolicyGenerationHint hint;
    
    /**
     * 추가 컨텍스트 정보
     */
    private Map<String, Object> additionalContext;
    
    /**
     * 이벤트 ID (원본 이벤트 추적용)
     */
    private String eventId;
    
    /**
     * 컨텍스트 생성 시간
     */
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
    
    /**
     * 위협 정보
     */
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
    
    /**
     * 대응 정보
     */
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
    
    /**
     * 정책 생성 힌트
     */
    @Data
    public static class PolicyGenerationHint {
        private String preferredPolicyType;  // ACCESS_CONTROL, RATE_LIMITING, BLOCKING 등
        private String scope;                 // GLOBAL, RESOURCE_SPECIFIC, USER_SPECIFIC 등
        private Integer priority;              // 정책 우선순위
        private Boolean requiresApproval;      // 승인 필요 여부
        private String targetAudience;         // 정책 적용 대상
    }
    
    /**
     * 빌더 패턴을 위한 메서드들
     */
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
    
    /**
     * 위협 심각도 기반 보안 레벨 자동 설정
     */
    public void adjustSecurityLevelBySeverity() {
        // SecurityLevel은 final이므로 생성 후 변경할 수 없음
        // 이 메서드는 미래 확장을 위해 비워둘
        // 필요한 경우 새로운 컨텍스트를 생성해야 함
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