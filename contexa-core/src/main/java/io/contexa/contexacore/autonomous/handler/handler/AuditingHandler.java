package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class AuditingHandler implements SecurityEventHandler {

    private final CentralAuditFacade centralAuditFacade;

    @Override
    public boolean handle(SecurityEventContext context) {
        if (centralAuditFacade == null) {
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

            String action = result.getAction();
            String decision = (action != null && !action.isBlank()) ? action.toUpperCase() : "UNANALYZED";
            String targetResource = getResourceFromMetadata(event);

            Map<String, Object> details = new HashMap<>();
            details.put("eventId", event.getEventId());
            details.put("decision", result.getAction());
            details.put("llmProposedAction", result.getProposedAction());
            details.put("riskScore", result.getRiskScore());
            details.put("confidence", result.getConfidence());
            details.put("llmAuditConfidence", result.resolveAuditConfidence());
            details.put("reasoning", result.getReasoning());
            details.put("autonomyConstraintApplied", result.getAutonomyConstraintApplied());
            details.put("autonomyConstraintSummary", result.getAutonomyConstraintSummary());
            details.put("autonomyConstraintReasons", result.getAutonomyConstraintReasons());
            details.put("severity", event.getSeverity() != null ? event.getSeverity().toString() : null);
            details.put("aiAnalysisLevel", result.getAiAnalysisLevel());
            details.put("processingTimeMs", processingTimeMs);
            details.put("eventSource", event.getSource() != null ? event.getSource().toString() : null);
            details.put("eventTimestamp", event.getTimestamp() != null ? event.getTimestamp().toString() : null);
            if (targetResource != null) {
                details.put("targetResource", targetResource);
            }

            centralAuditFacade.recordSync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.SECURITY_DECISION)
                    .principalName(event.getUserId())
                    .eventSource("CORE")
                    .clientIp(event.getSourceIp())
                    .sessionId(event.getSessionId())
                    .userAgent(event.getUserAgent())
                    .resourceIdentifier(targetResource != null ? targetResource : event.getEventId())
                    .resourceUri(targetResource)
                    .action("SECURITY_DECISION")
                    .decision(decision)
                    .reason(result.getReasoning())
                    .outcome(result.isSuccess() ? "COMPLETED" : "FAILED")
                    .riskScore(result.getRiskScore())
                    .details(details)
                    .build());

            return true;

        } catch (Exception e) {
            log.error("[AuditingHandler] Error recording audit log for event: {}", event.getEventId(), e);
            return true;
        }
    }

    private String getResourceFromMetadata(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return null;
        }
        Object resource = event.getMetadata().get("targetResource");
        return resource != null ? resource.toString() : null;
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
