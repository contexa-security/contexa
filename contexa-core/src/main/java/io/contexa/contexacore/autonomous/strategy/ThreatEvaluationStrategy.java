package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.domain.SecurityContext;

import java.util.List;
import java.util.Map;

/**
 * 위협 평가 전략 인터페이스
 * 
 * Strategy 패턴을 구현하여 다양한 위협 평가 방법을 제공합니다.
 * MITRE ATT&CK, NIST CSF, CIS Controls 등 다양한 프레임워크별 전략을 구현할 수 있습니다.
 */
public interface ThreatEvaluationStrategy {
    
    /**
     * 보안 이벤트 평가 (기본 방법)
     * 
     * @param event 보안 이벤트
     * @return 위협 평가 결과
     */
    ThreatAssessment evaluate(SecurityEvent event);
    
    /**
     * SecurityContext를 활용한 향상된 위협 평가
     * Zero Trust 아키텍처의 핵심 - 사용자 컨텍스트를 활용한 위협 평가
     * 
     * @param event 보안 이벤트
     * @param context 사용자 보안 컨텍스트
     * @return 컨텍스트 기반 향상된 위협 평가 결과
     */
    default ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        // 기본 구현은 일반 evaluate 호출
        // 구체적인 전략에서 SecurityContext 활용하도록 오버라이드
        return evaluate(event);
    }
    
    /**
     * Map 형태의 컨텍스트를 활용한 위협 평가 (호환성)
     * 
     * @param contextData 컨텍스트 데이터
     * @return 위협 평가 결과
     */
    default ThreatAssessment evaluate(Map<String, Object> contextData) {
        // Map을 SecurityEvent로 변환 (기본 구현)
        SecurityEvent event = SecurityEvent.builder()
            .eventId("map-" + System.currentTimeMillis())
            .eventType(SecurityEvent.EventType.UNKNOWN)
            .source(SecurityEvent.EventSource.UNKNOWN)
            .build();
        return evaluate(event);
    }
    
    /**
     * 위협 지표 추출
     * 
     * @param event 보안 이벤트
     * @return 위협 지표 리스트
     */
    List<ThreatIndicator> extractIndicators(SecurityEvent event);
    
    /**
     * 전략 이름
     * 
     * @return 전략 이름
     */
    String getStrategyName();
    
    /**
     * 전략 설명
     * 
     * @return 전략 설명
     */
    default String getDescription() {
        return getStrategyName() + " threat evaluation strategy";
    }
    
    /**
     * 프레임워크 매핑
     * 
     * @param event 보안 이벤트
     * @return 프레임워크 매핑 정보
     */
    Map<String, String> mapToFramework(SecurityEvent event);
    
    /**
     * 권장 액션 도출
     * 
     * @param event 보안 이벤트
     * @return 권장 액션 리스트
     */
    List<String> getRecommendedActions(SecurityEvent event);
    
    /**
     * 위험 점수 계산
     * 
     * @param indicators 위협 지표들
     * @return 위험 점수 (0.0 ~ 1.0)
     */
    double calculateRiskScore(List<ThreatIndicator> indicators);
    
    /**
     * 신뢰도 점수 계산
     * 
     * @param event 보안 이벤트
     * @return 신뢰도 점수 (0.0 ~ 1.0)
     */
    default double calculateConfidenceScore(SecurityEvent event) {
        // 기본 구현: 이벤트 소스와 메타데이터 기반 계산
        double baseScore = 0.5;
        
        if (event.getConfidenceScore() != null) {
            baseScore = event.getConfidenceScore();
        }
        
        // 소스별 가중치
        if (event.getSource() != null) {
            switch (event.getSource()) {
                case IDS:
                case IPS:
                    baseScore += 0.2;
                    break;
                case SIEM:
                    baseScore += 0.15;
                    break;
                case FIREWALL:
                case WAF:
                    baseScore += 0.1;
                    break;
                case MANUAL:
                    baseScore -= 0.1;
                    break;
                default:
                    // 기본값 유지
            }
        }
        
        // 규칙 매칭이 있으면 신뢰도 증가
        if (event.getRuleId() != null && !event.getRuleId().isEmpty()) {
            baseScore += 0.1;
        }
        
        // MITRE 매핑이 있으면 신뢰도 증가
        if (event.getMitreAttackId() != null && !event.getMitreAttackId().isEmpty()) {
            baseScore += 0.1;
        }
        
        return Math.min(Math.max(baseScore, 0.0), 1.0);
    }
    
    /**
     * 전략 활성 여부
     * 
     * @return 활성 여부
     */
    default boolean isEnabled() {
        return true;
    }
    
    /**
     * 전략 우선순위
     * 
     * @return 우선순위 (낮을수록 높은 우선순위)
     */
    default int getPriority() {
        return 100;
    }
    
    /**
     * 특정 이벤트 타입 처리 가능 여부
     * 
     * @param eventType 이벤트 타입
     * @return 처리 가능 여부
     */
    default boolean canEvaluate(SecurityEvent.EventType eventType) {
        return true; // 기본적으로 모든 타입 처리
    }
    
    /**
     * 임계값 설정
     * 
     * @return 위험 수준별 임계값
     */
    default Map<String, Double> getThresholds() {
        return Map.of(
            "CRITICAL", 0.9,
            "HIGH", 0.7,
            "MEDIUM", 0.5,
            "LOW", 0.3,
            "INFO", 0.1
        );
    }
}