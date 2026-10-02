package io.contexa.demo.platform.observation.support;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.demo.observation.learning.dto.LearningSource;
import java.util.UUID;

public abstract class AbstractNativeDecisionObservationAspect extends AbstractNativeObservationAspect {

    protected LearningSource source(String username, SecurityDecision decision, SecurityEvent event) {
        if (event == null || event.getMetadata() == null || decision == null
                || decision.resolveAutonomousAction() == null) {
            return null;
        }
        Object request = event.getMetadata().get("requestId");
        Object generation = event.getMetadata().get("eventProcessingOwnerToken");
        if (!(request instanceof String requestId) || !(generation instanceof String owner)
                || owner.isBlank() || event.getEventId() == null) {
            return null;
        }
        UUID parsed = UUID.fromString(requestId);
        if (!parsed.toString().equals(requestId)) {
            return null;
        }
        return new LearningSource(UUID.randomUUID(), parsed, event.getEventId(), owner, username,
                decision.resolveAutonomousAction().name());
    }
}
