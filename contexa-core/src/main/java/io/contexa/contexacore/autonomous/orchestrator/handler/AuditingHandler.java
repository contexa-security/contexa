package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.util.Map;

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
            auditSecurityEvent(context);
            auditThreatAssessment(context);
            auditProcessingDecision(context);

            return true;

        } catch (Exception e) {
            log.error("[AuditingHandler] Error recording audit logs for event: {}", event.getEventId(), e);
            return true;
        }
    }

    private void auditSecurityEvent(SecurityEventContext context) {
        try {
            SecurityEvent event = context.getSecurityEvent();
            String agentId = (String) context.getMetadata().get("agentId");
            if (agentId == null) {
                agentId = "security-plane-agent";
            }

            String auditContext = String.format("Processing by %s - Status: %s",
                    getName(), context.getProcessingStatus());

            auditLogger.auditSecurityEvent(event, agentId, auditContext);

        } catch (Exception e) {
            log.error("[AuditingHandler] Failed to audit security event", e);
        }
    }

    private void auditThreatAssessment(SecurityEventContext context) {
        try {
            Object resultObj = context.getMetadata().get("processingResult");
            if (!(resultObj instanceof ProcessingResult result)) {
                return;
            }

            SecurityEvent event = context.getSecurityEvent();
            String action = result.getAction() != null ? result.getAction() : "ALLOW";

            ThreatAssessment assessment = ThreatAssessment.builder()
                    .assessmentId(event.getEventId() + "-assessment")
                    .riskScore(result.getRiskScore())
                    .confidence(result.getConfidence())
                    .description(result.getReasoning())
                    .evaluator("ColdPathEventProcessor-AI")
                    .action(action)
                    .assessedAt(LocalDateTime.now())
                    .build();

            String evaluator = "Layer" + result.getAiAnalysisLevel();
            long processingTime = result.getProcessingTimeMs();

            auditLogger.auditThreatAssessment(event, assessment, evaluator, processingTime);

        } catch (Exception e) {
            log.error("[AuditingHandler][AI Native] Failed to audit threat assessment", e);
        }
    }

    private void auditProcessingDecision(SecurityEventContext context) {
        try {
            Object resultObj = context.getMetadata().get("processingResult");
            if (!(resultObj instanceof ProcessingResult result)) {
                return;
            }

            SecurityEvent event = context.getSecurityEvent();
            ProcessingMode mode = (ProcessingMode) context.getMetadata().get("processingMode");
            if (mode == null) {
                mode = ProcessingMode.AI_ANALYSIS;
            }

            String router = "ProcessingExecutionHandler";
            String reason = "AI Native - LLM analysis";

            Map<String, Object> decisionContext = Map.of(
                    "riskScore", result.getRiskScore(),
                    "confidence", result.getConfidence(),
                    "action", result.getAction() != null ? result.getAction() : "UNKNOWN",
                    "processingMode", mode.toString(),
                    "timestamp", System.currentTimeMillis()
            );

            auditLogger.auditProcessingDecision(event, mode, router, reason, decisionContext);

        } catch (Exception e) {
            log.error("[AuditingHandler] Failed to audit processing decision", e);
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
