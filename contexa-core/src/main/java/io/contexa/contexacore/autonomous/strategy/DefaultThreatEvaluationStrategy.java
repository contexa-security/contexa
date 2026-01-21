package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.domain.SecurityContext;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
public class DefaultThreatEvaluationStrategy implements ThreatEvaluationStrategy {
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {

        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName())
            .riskScore(Double.NaN)  
            .indicators(new ArrayList<>())
            .recommendedActions(List.of("LLM_ANALYSIS_REQUIRED"))  
            .confidence(Double.NaN)  
            .action("ESCALATE")  
            .build();
    }

    @Override
    public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        return new ArrayList<>();
    }
    
    @Override
    public String getStrategyName() {
        return "DEFAULT";
    }

    public Map<String, String> mapToFramework(SecurityEvent event) {
        return Map.of("FRAMEWORK", "BASIC");
    }
    
    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        
        return List.of("LLM_ANALYSIS_REQUIRED");
    }

    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {

        return Double.NaN;
    }

    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {

        return evaluate(event);
    }

}