package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

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
            log.debug("[AuditingHandler] Audit logger not available, skipping audit");
            return true; 
        }

        SecurityEvent event = context.getSecurityEvent();
        log.debug("[AuditingHandler] Recording audit logs for event: {}", event.getEventId());

        try {
            
            auditSecurityEvent(context);

            
            auditThreatAssessment(context);

            
            auditProcessingDecision(context);

            
            

            context.addMetadata("auditRecorded", true);
            context.addMetadata("auditTimestamp", System.currentTimeMillis());

            log.debug("[AuditingHandler] Audit logs recorded for event: {}", event.getEventId());
            return true; 

        } catch (Exception e) {
            log.error("[AuditingHandler] Error recording audit logs for event: {}", event.getEventId(), e);
            
            context.addMetadata("auditError", e.getMessage());
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
            SecurityEventContext.AIAnalysisResult aiResult = context.getAiAnalysisResult();
            if (aiResult == null) {
                return;
            }

            SecurityEvent event = context.getSecurityEvent();

            
            
            String action = determineActionFromRiskScore(aiResult.getThreatLevel());

            
            
            ThreatAssessment assessment = ThreatAssessment.builder()
                .assessmentId((String) context.getMetadata().get("threatAssessmentId"))
                .riskScore(aiResult.getThreatLevel())
                .confidence(aiResult.getConfidenceScore())
                .description(aiResult.getSummary())  
                .evaluator(aiResult.getAiModel())
                .action(action)  
                .assessedAt(LocalDateTime.now())
                .build();

            String evaluator = (String) context.getMetadata().get("evaluator");
            if (evaluator == null) {
                evaluator = aiResult.getAiModel();
            }

            String strategy = "IntegratedThreatEvaluator";
            if (Boolean.FALSE.equals(context.getMetadata().get("consensusAchieved"))) {
                strategy = "DynamicStrategySelector";
            }

            long processingTime = aiResult.getAnalysisTimeMs();

            auditLogger.auditThreatAssessment(event, assessment, evaluator, strategy, processingTime);

        } catch (Exception e) {
            log.error("[AuditingHandler][AI Native] Failed to audit threat assessment", e);
        }
    }

    
    private void auditProcessingDecision(SecurityEventContext context) {
        try {
            ProcessingMode mode = (ProcessingMode) context.getMetadata().get("processingMode");
            if (mode == null) {
                return;
            }

            SecurityEvent event = context.getSecurityEvent();
            String router = "RoutingDecisionHandler";
            String reason = (String) context.getMetadata().get("routingReason");

            Map<String, Object> decisionContext = Map.of(
                "riskScore", context.getAiAnalysisResult() != null ?
                    context.getAiAnalysisResult().getThreatLevel() : 0.0,
                "confidence", context.getAiAnalysisResult() != null ?
                    context.getAiAnalysisResult().getConfidenceScore() : 0.0,
                "processingMode", mode.toString(),
                "timestamp", System.currentTimeMillis()
            );

            auditLogger.auditProcessingDecision(event, mode, router, reason, decisionContext);

        } catch (Exception e) {
            log.error("[AuditingHandler] Failed to audit processing decision", e);
        }
    }

    
    private String determineActionFromRiskScore(double riskScore) {
        
        
        return "ESCALATE";
    }

    @Override
    public String getName() {
        return "AuditingHandler";
    }

    @Override
    public int getOrder() {
        return 45; 
    }
}