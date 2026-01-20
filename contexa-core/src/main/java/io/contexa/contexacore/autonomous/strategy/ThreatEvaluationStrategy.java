package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.domain.SecurityContext;

import java.util.List;
import java.util.Map;


public interface ThreatEvaluationStrategy {
    
    
    ThreatAssessment evaluate(SecurityEvent event);
    
    
    List<String> getRecommendedActions(SecurityEvent event);
    
    
    double calculateRiskScore(List<ThreatIndicator> indicators);
    
    
    default double calculateConfidenceScore(SecurityEvent event) {
        
        
        
        return Double.NaN;
    }
    
    
    default boolean isEnabled() {
        return true;
    }
    
    
    default int getPriority() {
        return 100;
    }
    
    
    default boolean canEvaluate(SecurityEvent.Severity severity) {
        return true; 
    }

    
    String getStrategyName();

    
    default String getDescription() {
        return "Threat evaluation strategy";
    }

    
    default List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        return java.util.Collections.emptyList();
    }

    
    default ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        return evaluate(event);
    }

}