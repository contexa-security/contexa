package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

@Slf4j
@RequiredArgsConstructor
public class AuditingHandler implements SecurityEventHandler {

    @Autowired(required = false)
    private SecurityPlaneAuditLogger auditLogger;

    @Override
    public boolean handle(SecurityEventContext context) {
        if (auditLogger == null) {
            return true;
        }

        SecurityEvent event = context.getSecurityEvent();

        try {
            Object resultObj = context.getMetadata().get("processingResult");
            if (!(resultObj instanceof ProcessingResult result)) {
                return true;
            }

            long processingTimeMs = 0;
            SecurityEventContext.ProcessingMetrics metrics = context.getProcessingMetrics();
            if (metrics != null) {
                processingTimeMs = metrics.getResponseTimeMs();
            }

            auditLogger.auditSecurityDecision(event, result, processingTimeMs);

            return true;

        } catch (Exception e) {
            log.error("[AuditingHandler] Error recording audit log for event: {}", event.getEventId(), e);
            return true;
        }
    }

    @Override
    public String getName() {
        return "AuditingHandler";
    }

    @Override
    public int getOrder() {
        return 60;
    }
}
