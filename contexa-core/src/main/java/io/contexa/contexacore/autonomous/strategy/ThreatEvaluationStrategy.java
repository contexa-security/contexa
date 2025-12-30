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
     * AI Native 원칙:
     * - LLM 기반 전략은 LLM이 직접 confidence를 반환
     * - 비-LLM 전략은 @Override로 자체 구현
     * - 플랫폼은 규칙 기반 confidence 계산을 하지 않음
     *
     * @param event 보안 이벤트
     * @return 신뢰도 점수 (Double.NaN = LLM/자체 구현 필요)
     */
    default double calculateConfidenceScore(SecurityEvent event) {
        // AI Native: 플랫폼은 규칙 기반 confidence 계산 안 함
        // LLM 기반 전략(Layer1/2/3)은 LLM이 confidence 반환
        // 비-LLM 전략은 @Override로 자체 구현 필요
        return Double.NaN;
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
     * 특정 Severity 처리 가능 여부 (AI Native: eventType 제거)
     *
     * @param severity 이벤트 심각도
     * @return 처리 가능 여부
     */
    default boolean canEvaluate(SecurityEvent.Severity severity) {
        return true; // 기본적으로 모든 심각도 처리
    }

    /**
     * 전략 이름 반환
     *
     * @return 전략 이름
     */
    String getStrategyName();

    /**
     * 전략 설명 반환
     *
     * @return 전략 설명
     */
    default String getDescription() {
        return "Threat evaluation strategy";
    }

    /**
     * 위협 지표 추출
     *
     * @param event 보안 이벤트
     * @return 위협 지표 리스트
     */
    default List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        return java.util.Collections.emptyList();
    }

    /**
     * SecurityContext 기반 위협 평가 (Zero Trust)
     *
     * @param event 보안 이벤트
     * @param context 보안 컨텍스트
     * @return 위협 평가 결과
     */
    default ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        return evaluate(event);
    }

}