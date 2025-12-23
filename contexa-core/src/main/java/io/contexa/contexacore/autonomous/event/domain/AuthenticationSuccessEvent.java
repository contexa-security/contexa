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

    // 위험 평가 (AI Native v3.3.0)
    private Double trustScore;
    private RiskLevel riskLevel;  // LLM이 직접 설정
    private Map<String, Object> riskIndicators;
    private boolean anomalyDetected;

    // 세션 컨텍스트
    private Map<String, Object> sessionContext;
    private String previousSessionId;
    private LocalDateTime lastLoginTime;

    // 추가 메타데이터
    private Map<String, Object> metadata;
    
    /**
     * 위험 수준 반환 (AI Native v3.3.0)
     *
     * LLM이 직접 설정한 riskLevel 필드를 반환
     * 점수 기반 변환 로직 제거
     *
     * @return LLM이 설정한 riskLevel, 미설정시 UNKNOWN
     */
    public RiskLevel calculateRiskLevel() {
        // AI Native: LLM이 설정한 riskLevel 사용
        // 점수 기반 변환 로직 제거
        if (riskLevel != null) {
            return riskLevel;
        }

        // 이상 탐지 시스템의 독립적 신호
        if (anomalyDetected) {
            return RiskLevel.CRITICAL;
        }

        return RiskLevel.UNKNOWN;
    }
    
    
    public enum RiskLevel {
        MINIMAL, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
    }
}