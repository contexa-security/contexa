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

/**
 * SOAR Orchestration 처리 전략
 *
 * SOAR 워크플로우를 통한 자동화된 대응
 * 승인이 필요한 작업들의 오케스트레이션
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
@RequiredArgsConstructor
public class SoarOrchestrationStrategy implements ProcessingStrategy {

    @Autowired(required = false)
    private ColdPathEventProcessor coldPathProcessor;

    @Override
    public ProcessingResult process(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        log.info("[SoarOrchestrationStrategy] Starting SOAR orchestration for event: {}", event.getEventId());

        List<String> executedActions = new ArrayList<>();
        Map<String, Object> metadata = new HashMap<>();

        try {
            // 1. SOAR 워크플로우 준비
            prepareSoarWorkflow(context, executedActions);

            // 2. Cold Path를 통한 상세 분석 및 SOAR 실행
            if (coldPathProcessor != null) {
                double riskScore = context.getAiAnalysisResult() != null ?
                    context.getAiAnalysisResult().getThreatLevel() : 0.7;

                ProcessingResult coldResult = coldPathProcessor.processEvent(event, riskScore);

                if (coldResult.isSuccess()) {
                    executedActions.addAll(coldResult.getExecutedActions());
                    metadata.putAll(coldResult.getMetadata());
                }
            }

            // 3. SOAR 특화 액션
            executeSoarActions(context, executedActions);

            // 4. 승인 대기 상태 설정
            if (requiresApproval(context)) {
                context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.AWAITING_APPROVAL);
                executedActions.add("APPROVAL_REQUESTED");
                metadata.put("approvalRequired", true);
            }

            metadata.put("soarOrchestrated", true);
            metadata.put("workflowId", "SOAR-" + event.getEventId());

            log.info("[SoarOrchestrationStrategy] SOAR orchestration completed - event: {}, actions: {}",
                event.getEventId(), executedActions);

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

    /**
     * SOAR 워크플로우 준비
     */
    private void prepareSoarWorkflow(SecurityEventContext context, List<String> executedActions) {
        context.addResponseAction("SOAR_WORKFLOW_INIT", "SOAR workflow initialized");
        context.addMetadata("soarWorkflowStarted", System.currentTimeMillis());
        executedActions.add("SOAR_WORKFLOW_INITIALIZED");

        // 권장 액션들을 SOAR 워크플로우로 변환
        if (context.getAiAnalysisResult() != null &&
            context.getAiAnalysisResult().getRecommendedActions() != null) {

            Map<String, String> recommendedActions = context.getAiAnalysisResult().getRecommendedActions();
            for (Map.Entry<String, String> entry : recommendedActions.entrySet()) {
                context.addResponseAction("SOAR_ACTION_PLANNED", entry.getKey() + ": " + entry.getValue());
            }
        }
    }

    /**
     * SOAR 특화 액션 실행
     */
    private void executeSoarActions(SecurityEventContext context, List<String> executedActions) {
        // 인시던트 티켓 생성
        context.addResponseAction("INCIDENT_TICKET", "Incident ticket created in SOAR system");
        executedActions.add("INCIDENT_TICKET_CREATED");

        // 자동화 플레이북 실행
        context.addResponseAction("PLAYBOOK_EXECUTION", "Security playbook executed");
        executedActions.add("PLAYBOOK_EXECUTED");

        // 포렌식 데이터 수집
        context.addResponseAction("FORENSIC_COLLECTION", "Forensic data collection initiated");
        executedActions.add("FORENSIC_DATA_COLLECTED");
    }

    /**
     * 승인 필요 여부 확인
     */
    private boolean requiresApproval(SecurityEventContext context) {
        // 고위험 이벤트는 승인 필요
        if (context.isHighRisk()) {
            return true;
        }

        // 특정 액션들은 승인 필요
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