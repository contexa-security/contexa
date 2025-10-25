package io.contexa.contexacore.autonomous.event;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * 학습 가능한 이벤트 인터페이스
 * 
 * 자율 진화형 정책 패브릭에서 학습 루프의 시작점이 되는 모든 이벤트가 구현해야 하는 인터페이스
 * SecurityPlaneAgent나 AccessGovernanceLab 등에서 발생한 유의미한 보안 이벤트를
 * 정책 진화 시스템이 학습할 수 있도록 표준화된 형태로 제공
 * 
 * @author contexa
 * @since 1.0.0
 */
public interface LearnableEvent {
    
    /**
     * 이벤트 타입
     */
    enum EventType {
        /**
         * 동적 위협 대응 이벤트
         * SecurityPlaneAgent가 실시간 위협에 성공적으로 대응한 경우
         */
        DYNAMIC_THREAT_RESPONSE,
        
        /**
         * 정적 권한 분석 이벤트  
         * AccessGovernanceLab이 권한 감사에서 문제점을 발견한 경우
         */
        STATIC_ACCESS_ANALYSIS,
        
        /**
         * 성능 이상 이벤트
         * 시스템 성능 모니터링에서 이상을 감지한 경우
         */
        PERFORMANCE_ANOMALY,
        
        /**
         * 컴플라이언스 위반 이벤트
         * 규정 준수 감사에서 위반 사항을 발견한 경우
         */
        COMPLIANCE_VIOLATION,
        
        /**
         * 사용자 행동 이상 이벤트
         * 비정상적인 사용자 행동 패턴을 감지한 경우
         */
        USER_BEHAVIOR_ANOMALY
    }
    
    /**
     * 이벤트 고유 ID
     */
    String getEventId();
    
    /**
     * 이벤트 타입
     */
    EventType getEventType();
    
    /**
     * 이벤트 발생 시간
     */
    LocalDateTime getOccurredAt();
    
    /**
     * 이벤트 발생 소스 (예: SecurityPlaneAgent, AccessGovernanceLab)
     */
    String getSource();
    
    /**
     * 이벤트 심각도 (CRITICAL, HIGH, MEDIUM, LOW)
     */
    String getSeverity();
    
    /**
     * 이벤트 설명
     */
    String getDescription();
    
    /**
     * 이벤트 컨텍스트 데이터
     * 학습에 필요한 모든 상세 정보를 포함
     */
    Map<String, Object> getContext();
    
    /**
     * 대응 조치 결과 (성공/실패 여부)
     */
    boolean isResponseSuccessful();
    
    /**
     * 대응 조치 설명
     */
    String getResponseDescription();
    
    /**
     * 학습 우선순위 (높을수록 우선 처리)
     */
    default int getLearningPriority() {
        switch (getSeverity()) {
            case "CRITICAL":
                return 100;
            case "HIGH":
                return 75;
            case "MEDIUM":
                return 50;
            case "LOW":
                return 25;
            default:
                return 10;
        }
    }
    
    /**
     * 정책 생성이 필요한지 여부
     */
    default boolean requiresPolicyGeneration() {
        return isResponseSuccessful() && 
               (getEventType() == EventType.DYNAMIC_THREAT_RESPONSE || 
                getEventType() == EventType.STATIC_ACCESS_ANALYSIS);
    }
}