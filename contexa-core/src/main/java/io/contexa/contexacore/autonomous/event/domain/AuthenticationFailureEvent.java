package io.contexa.contexacore.autonomous.event.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * 인증 실패 이벤트
 *
 * 실패한 인증 시도에 대한 상세 정보를 포함하여 AI가 공격 패턴을 분석합니다.
 *
 * ApplicationEvent를 상속하지 않는 순수 DTO입니다.
 * ApplicationEventPublisher.publishEvent(Object)로 발행 가능합니다.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticationFailureEvent {

    private String eventId;
    private String userId;    // Zero Trust를 위한 사용자 식별자 (username과 동일)
    private String username;  // 시도된 사용자명
    private String sessionId;
    private LocalDateTime eventTimestamp;

    // 네트워크 정보
    private String sourceIp;
    private String userAgent;
    private String deviceId;

    // 실패 정보
    private String failureReason;
    private String exceptionClass;
    private String exceptionMessage;
    private int failureCount;  // 연속 실패 횟수

    // 인증 컨텍스트
    private String authenticationType; // PRIMARY, MFA, PASSKEY 등
    private String attemptedMethod;

    // 위험 평가
    private Double riskScore;
    private Map<String, Object> attackIndicators;
    private boolean bruteForceDetected;
    private boolean credentialStuffingDetected;

    // 추가 메타데이터
    private Map<String, Object> metadata;
    
    /**
     * 공격 유형 판단
     */
    public AttackType determineAttackType() {
        if (bruteForceDetected) {
            return AttackType.BRUTE_FORCE;
        }
        if (credentialStuffingDetected) {
            return AttackType.CREDENTIAL_STUFFING;
        }
        if (failureCount > 10) {
            return AttackType.SUSTAINED_ATTACK;
        }
        if (failureCount > 5) {
            return AttackType.SUSPICIOUS;
        }
        return AttackType.NORMAL;
    }
    
    public enum AttackType {
        NORMAL, SUSPICIOUS, BRUTE_FORCE, CREDENTIAL_STUFFING, SUSTAINED_ATTACK
    }
}