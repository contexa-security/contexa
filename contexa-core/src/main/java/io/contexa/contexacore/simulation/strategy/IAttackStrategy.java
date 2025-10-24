package io.contexa.contexacore.simulation.strategy;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * 공격 전략 기본 인터페이스
 *
 * 모든 공격 전략이 구현해야 하는 기본 계약을 정의합니다.
 * Strategy Pattern을 통해 다양한 공격을 유연하게 실행할 수 있습니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
public interface IAttackStrategy {

    /**
     * 공격 실행
     *
     * @param context 공격 컨텍스트
     * @return 공격 결과
     */
    AttackResult execute(AttackContext context);

    /**
     * 이벤트 발행자 설정
     *
     * @param eventPublisher 이벤트 발행자
     */
    default void setEventPublisher(SimulationEventPublisher eventPublisher) {
        // Default implementation - can be overridden if needed
    }
    
    /**
     * 공격 유형 반환
     * 
     * @return 공격 유형
     */
    AttackResult.AttackType getType();
    
    /**
     * 공격 우선순위 (높을수록 먼저 실행)
     * 
     * @return 우선순위 (0-100)
     */
    int getPriority();
    
    /**
     * 공격 카테고리
     * 
     * @return 공격 카테고리
     */
    AttackCategory getCategory();
    
    /**
     * 공격 설정 검증
     * 
     * @param context 공격 컨텍스트
     * @return 유효한 설정인지 여부
     */
    boolean validateContext(AttackContext context);
    
    /**
     * 예상 실행 시간
     * 
     * @return 예상 소요 시간 (밀리초)
     */
    long getEstimatedDuration();
    
    /**
     * 공격 설명
     * 
     * @return 공격에 대한 상세 설명
     */
    String getDescription();
    
    /**
     * 필요한 권한 수준
     * 
     * @return 권한 수준 (NONE, LOW, MEDIUM, HIGH)
     */
    RequiredPrivilege getRequiredPrivilege();
    
    /**
     * 공격 성공 기준
     * 
     * @return 성공 기준 설명
     */
    String getSuccessCriteria();
    
    /**
     * 공격 카테고리
     */
    enum AttackCategory {
        AUTHENTICATION("Authentication Attacks"),
        AUTHORIZATION("Authorization Attacks"),
        BEHAVIORAL("Behavioral Attacks"),
        ZERO_TRUST("Zero Trust Violations"),
        ACCOUNT_TAKEOVER("Account Takeover Attacks"),
        SESSION("Session Attacks"),
        MFA("Multi-Factor Authentication Attacks"),
        API("API Attacks"),
        AI_ML("AI/ML Attacks");
        
        private final String description;
        
        AttackCategory(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 필요 권한 수준
     */
    enum RequiredPrivilege {
        NONE("No privileges required"),
        LOW("Basic user privileges"),
        MEDIUM("Advanced user privileges"),
        HIGH("Administrative privileges");
        
        private final String description;
        
        RequiredPrivilege(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 공격 컨텍스트
     */
    class AttackContext {
        // 타겟 정보
        private String targetUser;
        private String targetResource;
        private String targetEndpoint;
        
        // 공격 설정
        private Map<String, Object> parameters;
        private Integer maxAttempts;
        private Long delayBetweenAttempts;
        private Boolean stealthMode;
        
        // 인증 정보
        private String sessionId;
        private String authToken;
        private Map<String, String> cookies;
        
        // 위치 정보
        private String sourceIp;
        private String location;
        private String deviceFingerprint;
        private String deviceId;
        private String userAgent;
        
        // 시간 정보
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        
        // 캠페인 정보
        private String campaignId;
        private String attackId;
        
        // Getters and Setters
        public String getTargetUser() { return targetUser; }
        public void setTargetUser(String targetUser) { this.targetUser = targetUser; }
        
        public String getTargetResource() { return targetResource; }
        public void setTargetResource(String targetResource) { this.targetResource = targetResource; }
        
        public String getTargetEndpoint() { return targetEndpoint; }
        public void setTargetEndpoint(String targetEndpoint) { this.targetEndpoint = targetEndpoint; }
        
        public Map<String, Object> getParameters() { return parameters; }
        public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
        
        public Integer getMaxAttempts() { return maxAttempts; }
        public void setMaxAttempts(Integer maxAttempts) { this.maxAttempts = maxAttempts; }
        
        public Long getDelayBetweenAttempts() { return delayBetweenAttempts; }
        public void setDelayBetweenAttempts(Long delayBetweenAttempts) { 
            this.delayBetweenAttempts = delayBetweenAttempts; 
        }
        
        public Boolean getStealthMode() { return stealthMode; }
        public void setStealthMode(Boolean stealthMode) { this.stealthMode = stealthMode; }
        
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }
        
        public String getAuthToken() { return authToken; }
        public void setAuthToken(String authToken) { this.authToken = authToken; }
        
        public Map<String, String> getCookies() { return cookies; }
        public void setCookies(Map<String, String> cookies) { this.cookies = cookies; }
        
        public String getSourceIp() { return sourceIp; }
        public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
        
        public String getLocation() { return location; }
        public void setLocation(String location) { this.location = location; }
        
        public String getDeviceFingerprint() { return deviceFingerprint; }
        public void setDeviceFingerprint(String deviceFingerprint) { 
            this.deviceFingerprint = deviceFingerprint; 
        }
        
        public String getDeviceId() { return deviceId; }
        public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
        
        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
        
        public String getUsername() { return targetUser; } // alias for targetUser
        public void setUsername(String username) { this.targetUser = username; }
        
        public LocalDateTime getStartTime() { return startTime; }
        public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }
        
        public LocalDateTime getEndTime() { return endTime; }
        public void setEndTime(LocalDateTime endTime) { this.endTime = endTime; }
        
        public String getCampaignId() { return campaignId; }
        public void setCampaignId(String campaignId) { this.campaignId = campaignId; }
        
        public String getAttackId() { return attackId; }
        public void setAttackId(String attackId) { this.attackId = attackId; }
        
        /**
         * 파라미터 가져오기 (타입 안전)
         */
        @SuppressWarnings("unchecked")
        public <T> T getParameter(String key, Class<T> type) {
            if (parameters == null) return null;
            Object value = parameters.get(key);
            if (value == null) return null;
            if (type.isInstance(value)) {
                return (T) value;
            }
            throw new ClassCastException("Parameter " + key + " is not of type " + type.getName());
        }
        
        /**
         * 파라미터 설정
         */
        public void setParameter(String key, Object value) {
            if (parameters == null) {
                parameters = new java.util.HashMap<>();
            }
            parameters.put(key, value);
        }
    }
}