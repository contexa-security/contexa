package io.contexa.springbootstartercontexa.event;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
@Qualifier("llmAnalysisEventListener")
public class LlmAnalysisEventListenerImpl implements LlmAnalysisEventListener {

    private final LlmAnalysisEventPublisher eventPublisher;

    @Override
    public void onContextCollected(String userId, String requestPath, String analysisRequirement) {
        eventPublisher.publishContextCollected(userId, requestPath, analysisRequirement);
    }

    @Override
    public void onLayer1Start(String userId, String requestPath) {
        eventPublisher.publishLayer1Start(userId, requestPath);
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double riskScore,
                                  Double confidence, String reasoning, String mitre, Long elapsedMs) {
        eventPublisher.publishLayer1Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason) {
        eventPublisher.publishLayer2Start(userId, requestPath, reason);
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double riskScore,
                                  Double confidence, String reasoning, String mitre, Long elapsedMs) {
        eventPublisher.publishLayer2Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath) {
        eventPublisher.publishDecisionApplied(userId, action, layer, requestPath);
    }

    @Override
    public void onError(String userId, String message) {
        eventPublisher.publishError(userId, message);
    }

    // Detailed pipeline events

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
    public void onThreatIndicators(String userId, String indicators, String recommendedActions) {
        eventPublisher.publishThreatIndicators(userId, indicators, recommendedActions);
    }
}
