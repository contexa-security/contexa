package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import reactor.core.publisher.Mono;

public interface PolicyEvolutionService {

    Mono<?> learnFromEvent(SecurityEvent event, String decision, String outcome);

    void evolvePolicy(SecurityEvent event, ThreatAssessment assessment);
}
