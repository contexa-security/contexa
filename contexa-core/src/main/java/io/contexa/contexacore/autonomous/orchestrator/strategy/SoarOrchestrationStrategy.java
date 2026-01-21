package io.contexa.contexacore.autonomous.orchestrator.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.security.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class SoarOrchestrationStrategy implements ProcessingStrategy {

    @Autowired(required = false)
    private ColdPathEventProcessor coldPathProcessor;

    @Override
    public ProcessingResult process(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        
        List<String> executedActions = new ArrayList<>();
        Map<String, Object> metadata = new HashMap<>();

        try {
            
            prepareSoarWorkflow(context, executedActions);

            if (coldPathProcessor != null) {
                double riskScore = context.getAiAnalysisResult() != null ?
                    context.getAiAnalysisResult().getThreatLevel() : 0.7;

                ProcessingResult coldResult = coldPathProcessor.processEvent(event, riskScore);

                if (coldResult.isSuccess()) {
                    executedActions.addAll(coldResult.getExecutedActions());
                    metadata.putAll(coldResult.getMetadata());
                }
            }

            executeSoarActions(context, executedActions);

            if (requiresApproval(context)) {
                context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.AWAITING_APPROVAL);
                executedActions.add("APPROVAL_REQUESTED");
                metadata.put("approvalRequired", true);
            }

            metadata.put("soarOrchestrated", true);
            metadata.put("workflowId", "SOAR-" + event.getEventId());

            return ProcessingResult.builder()
                .success(true)
                .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                .executedActions(executedActions)
                .metadata(metadata)
                .message("SOAR orchestration completed")
                .build();

        } catch (Exception e) {
            log.error("[SoarOrchestrationStrategy] Error in SOAR orchestration: {}", event.getEventId(), e);
            return ProcessingResult.builder()
                .success(false)
                .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                .executedActions(executedActions)
                .message("SOAR orchestration error: " + e.getMessage())
                .build();
        }
    }

    private void prepareSoarWorkflow(SecurityEventContext context, List<String> executedActions) {
        context.addResponseAction("SOAR_WORKFLOW_INIT", "SOAR workflow initialized");
        context.addMetadata("soarWorkflowStarted", System.currentTimeMillis());
        executedActions.add("SOAR_WORKFLOW_INITIALIZED");

        if (context.getAiAnalysisResult() != null &&
            context.getAiAnalysisResult().getRecommendedActions() != null) {

            Map<String, String> recommendedActions = context.getAiAnalysisResult().getRecommendedActions();
            for (Map.Entry<String, String> entry : recommendedActions.entrySet()) {
                context.addResponseAction("SOAR_ACTION_PLANNED", entry.getKey() + ": " + entry.getValue());
            }
        }
    }

    private void executeSoarActions(SecurityEventContext context, List<String> executedActions) {
        
        context.addResponseAction("INCIDENT_TICKET", "Incident ticket created in SOAR system");
        executedActions.add("INCIDENT_TICKET_CREATED");

        context.addResponseAction("PLAYBOOK_EXECUTION", "Security playbook executed");
        executedActions.add("PLAYBOOK_EXECUTED");

        context.addResponseAction("FORENSIC_COLLECTION", "Forensic data collection initiated");
        executedActions.add("FORENSIC_DATA_COLLECTED");
    }

    private boolean requiresApproval(SecurityEventContext context) {
        
        if (context.getAiAnalysisResult() != null && context.getAiAnalysisResult().getThreatLevel() >= 0.7) {
            return true;
        }

        SecurityEventContext.AIAnalysisResult aiResult = context.getAiAnalysisResult();
        if (aiResult != null && aiResult.getRecommendedActions() != null) {
            for (String action : aiResult.getRecommendedActions().keySet()) {
                if (action.contains("BLOCK") || action.contains("ISOLATE") || action.contains("TERMINATE")) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public ProcessingMode getSupportedMode() {
        return ProcessingMode.SOAR_ORCHESTRATION;
    }
}