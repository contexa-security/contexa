package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;

public interface ThreatEvaluator {

    ThreatAssessment evaluateIntegrated(SecurityEvent event);
}
