package io.contexa.springbootstartercontexa.event;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventObserver;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class LlmAnalysisEventListenerImpl implements LlmAnalysisEventObserver {

    private final LlmAnalysisEventPublisher eventPublisher;

    @Override
    public void onContextCollected(String userId, String requestPath, String analysisRequirement, Map<String, Object> metadata) {
        eventPublisher.publishContextCollected(userId, requestPath, analysisRequirement, metadata);
    }

    @Override
    public void onLayer1Start(String userId, String requestPath, Map<String, Object> metadata) {
        eventPublisher.publishLayer1Start(userId, requestPath, metadata);
    }

    @Override
    public void onLayer1Complete(
            String userId,
            String action,
            Double riskScore,
            Double confidence,
            String reasoning,
            String mitre,
            Long elapsedMs,
            Map<String, Object> metadata) {
        eventPublisher.publishLayer1Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs, metadata);
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason, Map<String, Object> metadata) {
        eventPublisher.publishLayer2Start(userId, requestPath, reason, metadata);
    }

    @Override
    public void onLayer2Complete(
            String userId,
            String action,
            Double riskScore,
            Double confidence,
            String reasoning,
            String mitre,
            Long elapsedMs,
            Map<String, Object> metadata) {
        eventPublisher.publishLayer2Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs, metadata);
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath, Map<String, Object> metadata) {
        eventPublisher.publishDecisionApplied(userId, action, layer, requestPath, metadata);
    }

    @Override
    public void onError(String userId, String message, Map<String, Object> metadata) {
        eventPublisher.publishError(userId, message, metadata);
    }

    @Override
    public void onHcadAnalysis(String userId, Map<String, Object> hcadData) {
        eventPublisher.publishHcadAnalysis(userId, hcadData);
    }

    @Override
    public void onSessionContextLoaded(String userId, Map<String, Object> sessionData) {
        eventPublisher.publishSessionContextLoaded(userId, sessionData);
    }

    @Override
    public void onRagSearchComplete(String userId, int matchedCount, long ragSearchMs) {
        eventPublisher.publishRagSearchComplete(userId, matchedCount, ragSearchMs);
    }

    @Override
    public void onBehaviorAnalysisComplete(String userId, Map<String, Object> behaviorData) {
        eventPublisher.publishBehaviorAnalysisComplete(userId, behaviorData);
    }

    @Override
    public void onLlmExecutionStart(String userId, String modelName, long promptBuildMs) {
        eventPublisher.publishLlmExecutionStart(userId, modelName, promptBuildMs);
    }

    @Override
    public void onLlmExecutionComplete(String userId, long llmExecutionMs, long responseParseMs) {
        eventPublisher.publishLlmExecutionComplete(userId, llmExecutionMs, responseParseMs);
    }

    @Override
    public void onEscalateProtectionTriggered(String userId, String requestPath, int escalateCount, int totalAnalysisCount, Map<String, Object> metadata) {
        Map<String, Object> merged = new LinkedHashMap<>();
        if (metadata != null) {
            merged.putAll(metadata);
        }
        merged.put("escalateCount", escalateCount);
        merged.put("totalAnalysisCount", totalAnalysisCount);
        eventPublisher.publishError(userId, "Escalate protection triggered", merged);
    }
}
