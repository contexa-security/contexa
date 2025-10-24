package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.domain.SecurityContext;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.*;

/**
 * 기본 위협 평가 전략 (폴백용)
 * 
 * 다른 전략이 사용 불가능한 경우 사용되는 기본 전략입니다.
 */
@Slf4j
public class DefaultThreatEvaluationStrategy implements ThreatEvaluationStrategy {
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.debug("Default threat evaluation for event: {}", event.getEventId());
        
        // 기본 위험 점수 계산
        double riskScore = calculateBasicRiskScore(event);
        
        // 위협 수준 결정
        ThreatAssessment.ThreatLevel threatLevel = determineBasicThreatLevel(riskScore);
        
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName())
            .threatLevel(threatLevel)
            .riskScore(riskScore)
            .indicators(new ArrayList<>())
            .recommendedActions(getBasicRecommendedActions(threatLevel))
            .confidence(0.5)
            .build();
    }
    
    private double calculateBasicRiskScore(SecurityEvent event) {
        double score = 0.3; // 기본 점수
        
        // Severity 기반 조정
        if (event.getSeverity() != null) {
            switch (event.getSeverity()) {
                case CRITICAL -> score += 0.5;
                case HIGH -> score += 0.3;
                case MEDIUM -> score += 0.1;
                case LOW -> score += 0.05;
                default -> { }
            }
        }
        
        // 이벤트 타입 기반 조정
        if (event.getEventType() != null) {
            switch (event.getEventType()) {
                case INTRUSION_ATTEMPT, INTRUSION_SUCCESS -> score += 0.3;
                case AUTH_FAILURE, SUSPICIOUS_ACTIVITY -> score += 0.2;
                case AUTH_SUCCESS, ACCESS_VIOLATION -> score += 0.1;
                default -> { }
            }
        }
        
        return Math.min(1.0, score);
    }
    
    private ThreatAssessment.ThreatLevel determineBasicThreatLevel(double riskScore) {
        if (riskScore >= 0.9) return ThreatAssessment.ThreatLevel.CRITICAL;
        if (riskScore >= 0.7) return ThreatAssessment.ThreatLevel.HIGH;
        if (riskScore >= 0.5) return ThreatAssessment.ThreatLevel.MEDIUM;
        if (riskScore >= 0.3) return ThreatAssessment.ThreatLevel.LOW;
        return ThreatAssessment.ThreatLevel.INFO;
    }
    
    private List<String> getBasicRecommendedActions(ThreatAssessment.ThreatLevel level) {
        return switch (level) {
            case CRITICAL -> List.of("IMMEDIATE_RESPONSE", "ISOLATE", "ALERT_SOC");
            case HIGH -> List.of("INVESTIGATE", "MONITOR_CLOSELY", "ALERT_TEAM");
            case MEDIUM -> List.of("MONITOR", "LOG", "REVIEW");
            case LOW -> List.of("LOG", "TRACK");
            default -> List.of("LOG");
        };
    }
    
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
        double riskScore = calculateBasicRiskScore(event);
        ThreatAssessment.ThreatLevel level = determineBasicThreatLevel(riskScore);
        return getBasicRecommendedActions(level);
    }
    
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        return indicators.size() * 0.1;
    }
    
    /**
     * SecurityContext를 활용한 향상된 위협 평가
     * Zero Trust 아키텍처 - 사용자 컨텍스트 기반 위협 평가
     */
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        log.debug("Context-aware threat evaluation for event: {} with user context", event.getEventId());
        
        // 기본 평가 수행
        ThreatAssessment basicAssessment = evaluate(event);
        
        if (context == null) {
            return basicAssessment;
        }
        
        // SecurityContext 기반 추가 분석
        double contextAdjustment = calculateContextAdjustment(context);
        double enhancedRiskScore = Math.min(1.0, basicAssessment.getRiskScore() + contextAdjustment);
        
        // Trust Score 기반 조정
        if (context.getTrustScore() != null) {
            // Trust Score가 낮을수록 위험 점수 증가
            double trustFactor = (1.0 - context.getTrustScore()) * 0.3;
            enhancedRiskScore = Math.min(1.0, enhancedRiskScore + trustFactor);
        }
        
        // 향상된 위협 수준 결정
        ThreatAssessment.ThreatLevel enhancedThreatLevel = determineBasicThreatLevel(enhancedRiskScore);
        
        // 컨텍스트 기반 추가 지표
        List<String> contextIndicators = extractContextIndicators(context);
        
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName() + "-WithContext")
            .threatLevel(enhancedThreatLevel)
            .riskScore(enhancedRiskScore)
            .indicators(contextIndicators)
            .recommendedActions(getContextAwareActions(enhancedThreatLevel, context))
            .confidence(calculateContextConfidence(context))
            .metadata(Map.of(
                "original_risk_score", basicAssessment.getRiskScore(),
                "context_adjustment", contextAdjustment,
                "trust_score", context.getTrustScore(),
                "user_id", context.getUserId()
            ))
            .build();
    }
    
    /**
     * SecurityContext 기반 위험 점수 조정 계산
     */
    private double calculateContextAdjustment(SecurityContext context) {
        double adjustment = 0.0;
        
        // 실패 카운터 확인
        if (context.getFailureCounters() != null && !context.getFailureCounters().isEmpty()) {
            int totalFailures = context.getFailureCounters().values().stream()
                .mapToInt(Integer::intValue).sum();
            adjustment += Math.min(0.3, totalFailures * 0.05); // 최대 0.3 증가
        }
        
        // 위협 지표 확인
        if (context.getThreatIndicators() != null && !context.getThreatIndicators().isEmpty()) {
            adjustment += Math.min(0.2, context.getThreatIndicators().size() * 0.05); // 최대 0.2 증가
        }
        
        // 과거 보안 인시던트 확인
        if (context.getSecurityIncidents() != null && !context.getSecurityIncidents().isEmpty()) {
            adjustment += Math.min(0.25, context.getSecurityIncidents().size() * 0.1); // 최대 0.25 증가
        }
        
        return adjustment;
    }
    
    /**
     * 컨텍스트에서 위협 지표 추출
     */
    private List<String> extractContextIndicators(SecurityContext context) {
        List<String> indicators = new ArrayList<>();
        
        if (context.getTrustScore() != null && context.getTrustScore() < 0.3) {
            indicators.add("LOW_TRUST_SCORE");
        }
        
        if (context.getFailureCounters() != null) {
            int totalFailures = context.getFailureCounters().values().stream()
                .mapToInt(Integer::intValue).sum();
            if (totalFailures > 5) {
                indicators.add("HIGH_FAILURE_COUNT");
            }
        }
        
        if (context.getThreatIndicators() != null && !context.getThreatIndicators().isEmpty()) {
            indicators.add("EXISTING_THREAT_INDICATORS");
        }
        
        if (context.getSecurityIncidents() != null && !context.getSecurityIncidents().isEmpty()) {
            indicators.add("SECURITY_INCIDENT_HISTORY");
        }
        
        return indicators;
    }
    
    /**
     * 컨텍스트를 고려한 권장 액션
     */
    private List<String> getContextAwareActions(ThreatAssessment.ThreatLevel level, SecurityContext context) {
        List<String> actions = new ArrayList<>(getBasicRecommendedActions(level));
        
        // Trust Score가 매우 낮은 경우
        if (context.getTrustScore() != null && context.getTrustScore() < 0.2) {
            actions.add("REQUIRE_ADDITIONAL_AUTHENTICATION");
            actions.add("RESTRICT_SENSITIVE_OPERATIONS");
        }
        
        // 반복된 실패가 있는 경우
        if (context.getFailureCounters() != null) {
            int totalFailures = context.getFailureCounters().values().stream()
                .mapToInt(Integer::intValue).sum();
            if (totalFailures > 10) {
                actions.add("TEMPORARY_ACCOUNT_LOCK");
                actions.add("SECURITY_TEAM_NOTIFICATION");
            }
        }
        
        return actions;
    }
    
    /**
     * 컨텍스트 기반 신뢰도 계산
     */
    private double calculateContextConfidence(SecurityContext context) {
        double baseConfidence = 0.5;
        
        // Trust Score가 있으면 신뢰도 증가
        if (context.getTrustScore() != null) {
            baseConfidence += 0.2;
        }
        
        // 풍부한 컨텍스트 데이터가 있으면 신뢰도 증가
        if (context.getBehaviorPatterns() != null && !context.getBehaviorPatterns().isEmpty()) {
            baseConfidence += 0.1;
        }
        
        if (context.getAccessPatterns() != null && !context.getAccessPatterns().isEmpty()) {
            baseConfidence += 0.1;
        }
        
        return Math.min(1.0, baseConfidence);
    }
}