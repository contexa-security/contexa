package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;

public interface ThreatEvaluationStrategy {

    ThreatAssessment evaluate(SecurityEvent event);

    String getStrategyName();

}