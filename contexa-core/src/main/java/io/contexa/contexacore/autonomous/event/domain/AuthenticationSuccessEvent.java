package io.contexa.contexacore.autonomous.event.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Zero Trust 인증 성공 이벤트
 *
 * 모든 성공한 인증에 대한 상세 정보를 포함하여 AI가 실시간으로
 * 이상 패턴을 감지할 수 있도록 합니다.
 *
 * ApplicationEvent를 상속하지 않는 순수 DTO입니다.
 * ApplicationEventPublisher.publishEvent(Object)로 발행 가능합니다.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticationSuccessEvent {

    private String eventId;
    private String userId;  // 필수 - 사용자 행동 분석용
    private String username;
    private String sessionId;
    private LocalDateTime eventTimestamp;

    // 네트워크 정보
    private String sourceIp;
    private String userAgent;
    private String deviceId;

    // 인증 컨텍스트
    private String authenticationType; // PRIMARY, MFA, PASSKEY 등
    private boolean mfaCompleted;
    private String mfaMethod;

    // 위험 평가
    private Double trustScore;
    private Map<String, Object> riskIndicators;
    private boolean anomalyDetected;

    // 세션 컨텍스트
    private Map<String, Object> sessionContext;
    private String previousSessionId;
    private LocalDateTime lastLoginTime;

    // 추가 메타데이터
    private Map<String, Object> metadata;
    
    /**
     * 위험 수준 계산
     * 
     * 중요: trustScore는 이미 AI Vector Store RAG에 의해 평가된 값이므로
     * 재평가하지 않고 그대로 사용합니다. 이중 평가를 방지합니다.
     */
    public RiskLevel calculateRiskLevel() {
        // anomalyDetected는 별도의 이상 탐지 시스템에서 오는 독립적인 신호
        if (anomalyDetected) {
            return RiskLevel.CRITICAL;
        }
        
        // trustScore가 없으면 UNKNOWN
        if (trustScore == null) {
            return RiskLevel.UNKNOWN;
        }
        
        // trustScore는 이미 AI가 평가한 값이므로 직접 매핑만 수행
        // 하드코딩된 임계값을 사용하지 않고 UnifiedRiskEvaluator 사용 권장
        // 하위 호환성을 위해 남겨둠
        if (trustScore >= 0.8) return RiskLevel.MINIMAL;
        if (trustScore >= 0.6) return RiskLevel.LOW;
        if (trustScore >= 0.4) return RiskLevel.MEDIUM;
        if (trustScore >= 0.2) return RiskLevel.HIGH;
        return RiskLevel.CRITICAL;
    }
    
    
    public enum RiskLevel {
        MINIMAL, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
    }
}