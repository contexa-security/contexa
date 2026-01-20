package io.contexa.contexacore.autonomous.orchestrator;

import io.contexa.contexacore.autonomous.ISecurityPlaneAgent;
import io.contexa.contexacore.autonomous.event.IncidentCompletedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;


@Slf4j
@RequiredArgsConstructor
public class SecurityPlaneEventListener {

    private final ISecurityPlaneAgent securityPlaneAgent;

    
    @EventListener
    @Async
    public void onIncidentCompleted(IncidentCompletedEvent event) {
        try {
            String incidentId = event.getIncident().getId().toString();
            String resolvedBy = event.getResolvedBy();
            String resolutionMethod = event.getResolutionMethod();
            boolean wasSuccessful = event.wasSuccessful();

            log.info("[SecurityPlaneEventListener] Received IncidentCompletedEvent: {} resolved by {} using {} (success: {})",
                incidentId, resolvedBy, resolutionMethod, wasSuccessful);

            
            
            securityPlaneAgent.resolveIncident(incidentId, resolvedBy, resolutionMethod, wasSuccessful);

            log.debug("[SecurityPlaneEventListener] Successfully delegated incident completion to SecurityPlaneAgent");

        } catch (Exception e) {
            log.error("[SecurityPlaneEventListener] Failed to handle IncidentCompletedEvent: {}", event, e);
        }
    }
}