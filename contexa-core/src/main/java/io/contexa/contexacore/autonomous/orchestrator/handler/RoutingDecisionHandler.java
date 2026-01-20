package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.metrics.RoutingDecisionMetrics;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashMap;
import java.util.Map;


@Slf4j

@RequiredArgsConstructor
public class RoutingDecisionHandler implements SecurityEventHandler {

    @Autowired(required = false)
    private RoutingDecisionMetrics routingMetrics;

    
    @Override
    public boolean handle(SecurityEventContext context) {
        log.info("[RoutingDecisionHandler][AI Native] Processing event: {}", context.getSecurityEvent().getEventId());
        SecurityEvent event = context.getSecurityEvent();

        long startTime = System.nanoTime();

        try {
            
            ProcessingMode mode = ProcessingMode.AI_ANALYSIS;

            
            context.addMetadata("processingMode", mode);
            context.addMetadata("routingDecision", mode.toString());
            context.addMetadata("routingReason", "AI Native - all requests routed to LLM analysis");
            context.addMetadata("routingTimestamp", System.currentTimeMillis());
            context.addMetadata("requiresColdPath", true);

            
            context.addMetadata("isRealtime", mode.isRealtime());
            context.addMetadata("isBlocking", mode.isBlocking());
            context.addMetadata("needsEscalation", mode.needsEscalation());
            context.addMetadata("needsMonitoring", mode.needsMonitoring());
            context.addMetadata("needsHumanIntervention", mode.needsHumanIntervention());

            log.info("[RoutingDecisionHandler][AI Native] Event {} routed to Cold Path (LLM analysis)",
                event.getEventId());

            
            long duration = System.nanoTime() - startTime;
            if (routingMetrics != null) {
                routingMetrics.recordColdPath(duration, mode.toString());

                Map<String, Object> metadata = new HashMap<>();
                metadata.put("path_type", "cold");
                metadata.put("mode", mode.toString());
                metadata.put("duration", duration);
                metadata.put("event_id", event.getEventId());
                routingMetrics.recordEvent("routing_cold", metadata);
            }

            return true;

        } catch (Exception e) {
            log.error("[RoutingDecisionHandler][AI Native] Error routing event: {}", event.getEventId(), e);
            
            context.addMetadata("processingMode", ProcessingMode.AI_ANALYSIS);
            context.addMetadata("routingDecision", ProcessingMode.AI_ANALYSIS.toString());
            context.addMetadata("routingReason", "AI Native - error fallback to LLM analysis");
            context.addMetadata("requiresColdPath", true);
            return true;
        }
    }

    @Override
    public String getName() {
        return "RoutingDecisionHandler";
    }

    @Override
    public int getOrder() {
        return 40; 
    }

}