package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.domain.SecurityContext;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.*;

/**
 * 기본 위협 평가 전략 (폴백용) - AI Native
 *
 * 다른 전략이 사용 불가능한 경우 사용되는 기본 전략입니다.
 *
 * AI Native 원칙:
 * - 규칙 기반 점수 계산 제거 (riskScore, confidence는 LLM이 결정)
 * - LLM 분석 결과가 없으면 Double.NaN 반환
 * - ThreatLevel 임계값 매핑 제거 (LLM이 직접 결정)
 */
@Slf4j
public class DefaultThreatEvaluationStrategy implements ThreatEvaluationStrategy {
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.debug("[DefaultThreatEvaluationStrategy][AI Native] Default threat evaluation for event: {}", event.getEventId());

        // AI Native: 규칙 기반 점수 계산 제거
        // LLM 분석이 없는 폴백 상태이므로 NaN 반환
        // ThreatLevel도 LLM이 결정해야 하므로 null (가장 낮은 INFO 사용)

        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName())
            .threatLevel(ThreatAssessment.ThreatLevel.INFO)  // AI Native: LLM 분석 미수행 상태
            .riskScore(Double.NaN)  // AI Native: LLM이 결정해야 함
            .indicators(new ArrayList<>())
            .recommendedActions(List.of("LLM_ANALYSIS_REQUIRED"))  // AI Native: LLM 분석 필요
            .confidence(Double.NaN)  // AI Native: LLM이 결정해야 함
            .build();
    }
    
    // AI Native: 규칙 기반 점수 계산 메서드 제거
    // LLM이 riskScore를 직접 결정해야 함
    // private double calculateBasicRiskScore(SecurityEvent event) { ... }

    // AI Native: 임계값 기반 ThreatLevel 매핑 제거
    // LLM이 ThreatLevel을 직접 결정해야 함
    // private ThreatAssessment.ThreatLevel determineBasicThreatLevel(double riskScore) { ... }

    // AI Native: ThreatLevel 기반 권장 액션 매핑 제거
    // LLM이 권장 액션을 직접 결정해야 함
    // private List<String> getBasicRecommendedActions(ThreatAssessment.ThreatLevel level) { ... }
    
    @Override
    public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        return new ArrayList<>();
    }
    
    @Override
    public String getStrategyName() {
        return "DEFAULT";
    }
    
    @Override
    public Map<String, String> mapToFramework(SecurityEvent event) {
        return Map.of("FRAMEWORK", "BASIC");
    }
    
    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        // AI Native: LLM이 권장 액션을 직접 결정해야 함
        return List.of("LLM_ANALYSIS_REQUIRED");
    }

    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        // AI Native: LLM이 riskScore를 직접 결정해야 함
        // 규칙 기반 계산 (indicators.size() * 0.1) 제거
        return Double.NaN;
    }
    
    /**
     * SecurityContext를 활용한 향상된 위협 평가 - AI Native
     *
     * AI Native 원칙: 컨텍스트 기반 조정도 LLM이 담당
     * 플랫폼은 컨텍스트 정보를 LLM에 전달만 함
     */
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        log.debug("[DefaultThreatEvaluationStrategy][AI Native] Context-aware evaluation for event: {}", event.getEventId());

        // AI Native: 규칙 기반 컨텍스트 조정 제거
        // LLM이 컨텍스트를 분석하여 riskScore, ThreatLevel 등을 직접 결정해야 함
        return evaluate(event);
    }

    // AI Native: 규칙 기반 컨텍스트 조정 메서드들 제거
    // - calculateContextAdjustment(): Trust Score 기반 조정 제거
    // - extractContextIndicators(): 임계값 기반 지표 추출 제거
    // - getContextAwareActions(): 임계값 기반 액션 제거
    // - calculateContextConfidence(): 규칙 기반 신뢰도 계산 제거
}