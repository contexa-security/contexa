package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;

public interface ThreatEvaluationStrategy {

    ThreatAssessment evaluate(SecurityEvent event);

    default boolean isEnabled() {
        return true;
    }

    default int getPriority() {
        return 100;
    }

    default String getDescription() {
        return "Threat evaluation strategy";
    }

    default String getStrategyName() {
        return getClass().getSimpleName();
    }

    default boolean supports(SecurityEvent event) {
        return true;
    }

    default int getStrategyPriority() {
        return getPriority();
    }

}