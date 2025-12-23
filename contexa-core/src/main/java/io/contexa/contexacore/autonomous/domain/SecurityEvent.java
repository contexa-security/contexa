package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import io.contexa.contexacore.autonomous.tiered.SecurityDecision;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.HashMap;
import java.util.Map;

/**
 * Security Event
 * 
 * 보안 이벤트를 나타내는 도메인 객체
 * 24시간 자율 보안 평면에서 수집된 모든 보안 이벤트를 표현합니다.
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEvent {
    
    // 기본 필드
    @Builder.Default
    private String eventId = UUID.randomUUID().toString();
    
    @Builder.Default
    private EventType eventType = EventType.UNKNOWN;
    
    @Builder.Default
    private EventSource source = EventSource.UNKNOWN;
    
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();
    
    @Builder.Default
    private Severity severity = Severity.MEDIUM;
    
    @Builder.Default
    private String description = "Security event";
    
    // 네트워크 정보
    private String sourceIp;
    private String targetIp;
    private Integer sourcePort;
    private Integer targetPort;
    private String protocol;
    
    // 사용자 정보
    private String userId;  // Zero Trust 필수 - 사용자 식별자
    private String userName;
    private String sessionId;
    private String organizationId;
    private String userAgent;
    
    // AI Native: 위협 정보 필드 제거됨 (v3.0.0)
    // mitreAttackId, threatType, attackVector, confidenceScore
    // -> ThreatAssessment 또는 SecurityDecision에서 관리
    // -> 필요한 정보는 metadata에 저장

    // 메타데이터
    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();
    
    // AI Native: action 필드 제거됨 (v3.0.0)
    // -> SecurityDecision.action에서 관리
    // -> Zero Trust는 점수 기반이 아닌 ACTION 기반 의사결정

    private boolean blocked;

    // 추가 필드
    private String targetResource;  // Zero Trust - 접근 대상 리소스

    // AI Native: riskScore 필드 제거됨 (v3.0.0)
    // -> ThreatAssessment.riskScore 또는 SecurityDecision.riskScore 사용
    // -> Zero Trust 의사결정은 ACTION 기반, 점수는 감사/모니터링용

    @Builder.Default
    private Map<String, Object> details = new HashMap<>();
    
    /**
     * 이벤트 타입 열거형
     */
    public enum EventType {
        // 기본값
        UNKNOWN("Unknown Event"),
        
        // 인증 관련
        AUTH_FAILURE("Authentication Failure"),
        AUTH_SUCCESS("Authentication Success"),
        ACCESS_DENIED("Access Denied"),
        PRIVILEGE_ESCALATION("Privilege Escalation"),
        
        // 공격 관련
        INTRUSION_ATTEMPT("Intrusion Attempt"),
        INTRUSION_SUCCESS("Intrusion Success"),
        DATA_EXFILTRATION("Data Exfiltration"),
        MALWARE_DETECTED("Malware Detected"),
        BRUTE_FORCE("Brute Force Attack"),
        CREDENTIAL_STUFFING("Credential Stuffing"),
        ACCESS_CONTROL_VIOLATION("Access Control Violation"),
        
        // 탐지 관련
        ANOMALY_DETECTED("Anomaly Detected"),
        THREAT_DETECTED("Threat Detected"),
        NETWORK_SCAN("Network Scan"),
        SUSPICIOUS_ACTIVITY("Suspicious Activity"),
        
        // 공격 유형들
        SQL_INJECTION_ATTACK("SQL Injection Attack"),
        LATERAL_MOVEMENT("Lateral Movement"),
        DDOS_ATTACK("DDoS Attack"),
        PHISHING_ATTEMPT("Phishing Attempt"),
        MALWARE_DEPLOYMENT("Malware Deployment"),
        ZERO_DAY_EXPLOIT("Zero Day Exploit"),
        INSIDER_THREAT("Insider Threat"),
        RANSOMWARE_ATTACK("Ransomware Attack"),
        APT_CAMPAIGN("APT Campaign"),
        
        // 정책 관련
        POLICY_VIOLATION("Policy Violation"),
        CONFIGURATION_CHANGE("Configuration Change"),
        
        // 시스템 관련
        SYSTEM_COMPROMISE("System Compromise"),
        SYSTEM_ERROR("System Error"),
        
        // 인시던트 관련
        INCIDENT_CREATED("Incident Created"),
        INCIDENT_UPDATED("Incident Updated"),
        
        // 추가 이벤트 타입들
        DENIAL_OF_SERVICE("Denial of Service"),
        COMMAND_CONTROL("Command and Control"),
        
        // 자율 학습용 이벤트 타입
        ACCESS_VIOLATION("Access Violation"),
        SYSTEM_ALERT("System Alert");
        
        private final String displayName;
        
        EventType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    /**
     * 이벤트 소스 열거형
     */
    public enum EventSource {
        IDS("Intrusion Detection System"),
        IPS("Intrusion Prevention System"),
        SIEM("Security Information and Event Management"),
        FIREWALL("Firewall"),
        WAF("Web Application Firewall"),
        ENDPOINT("Endpoint Protection"),
        IAM("Identity and Access Management"),
        MANUAL("Manual Entry"),
        THREAT_INTEL("Threat Intelligence"),
        KAFKA("Kafka Stream"),
        REDIS("Redis Stream"),
        API("API Gateway"),
        UNKNOWN("Unknown Source");
        
        private final String description;
        
        EventSource(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 보안 이벤트 심각도 열거형
     */
    public enum Severity {
        CRITICAL("Critical", 10),
        HIGH("High", 8),
        MEDIUM("Medium", 5),
        LOW("Low", 3),
        INFO("Info", 1);
        
        private final String displayName;
        private final int score;
        
        Severity(String displayName, int score) {
            this.displayName = displayName;
            this.score = score;
        }
        
        public String getDisplayName() {
            return displayName;
        }
        
        public int getScore() {
            return score;
        }
        
        public static Severity fromScore(int score) {
            if (score >= 9) return CRITICAL;
            if (score >= 7) return HIGH;
            if (score >= 4) return MEDIUM;
            if (score >= 2) return LOW;
            return INFO;
        }
    }
    
    /**
     * 메타데이터 추가
     * 
     * @param key 키
     * @param value 값
     */
    public void addMetadata(String key, Object value) {
        if (this.metadata == null) {
            this.metadata = new HashMap<>();
        }
        this.metadata.put(key, value);
    }
    
    /**
     * 메타데이터 추가 (문자열)
     * 
     * @param key 키
     * @param value 값
     */
    public void addMetadata(String key, String value) {
        addMetadata(key, (Object) value);
    }
    
    /**
     * AI Native v3.3.0: action 기반 고위험 판단
     * LLM이 결정한 action으로 위험도 판단
     *
     * Severity 기반 isHighRisk() 제거됨 - Action 기반 판단 필수
     *
     * @param action LLM이 결정한 보안 액션
     * @return BLOCK 또는 ESCALATE이면 true
     */
    public boolean isHighRiskByAction(SecurityDecision.Action action) {
        return action == SecurityDecision.Action.BLOCK ||
               action == SecurityDecision.Action.ESCALATE;
    }

    /**
     * AI Native v3.3.0: 차단 가능한 이벤트 여부
     *
     * Severity 기반 판단 제거 - 이미 차단되지 않은 모든 이벤트는 잠재적으로 차단 가능
     * 실제 차단 여부는 LLM action으로 결정
     *
     * @return 아직 차단되지 않았으면 true
     */
    public boolean isBlockable() {
        return !blocked;
    }
    
    /**
     * 인증 관련 이벤트 여부
     * 
     * @return 인증 관련이면 true
     */
    public boolean isAuthenticationRelated() {
        return eventType == EventType.AUTH_FAILURE || 
               eventType == EventType.AUTH_SUCCESS ||
               eventType == EventType.PRIVILEGE_ESCALATION;
    }
    
    /**
     * 네트워크 관련 이벤트 여부
     * 
     * @return 네트워크 관련이면 true
     */
    public boolean isNetworkRelated() {
        return eventType == EventType.INTRUSION_ATTEMPT || 
               eventType == EventType.INTRUSION_SUCCESS ||
               eventType == EventType.NETWORK_SCAN;
    }
    
    /**
     * 인시던트 관련 이벤트 여부
     * 
     * @return 인시던트 관련이면 true
     */
    public boolean isIncidentRelated() {
        return eventType == EventType.INCIDENT_CREATED ||
               eventType == EventType.INCIDENT_UPDATED;
    }
    
    /**
     * Zero Trust를 위한 userId 검증
     * 
     * @return userId가 존재하면 true
     */
    public boolean hasUserId() {
        return userId != null && !userId.trim().isEmpty();
    }
    
    /**
     * Zero Trust 컨텍스트 키 생성
     * 사용자별 컨텍스트 추적을 위한 Redis 키
     * 
     * @return 사용자 컨텍스트 키
     */
    public String getUserContextKey() {
        if (!hasUserId()) {
            throw new IllegalStateException("UserId is required for Zero Trust context");
        }
        return "security:user:context:" + userId;
    }
    
    /**
     * 세션-사용자 매핑 키 생성
     * 
     * @return 세션 매핑 키
     */
    public String getSessionMappingKey() {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            return null;
        }
        return "security:session:user:" + sessionId;
    }
}