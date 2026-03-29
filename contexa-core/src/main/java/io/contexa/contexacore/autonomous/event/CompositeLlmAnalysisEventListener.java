package io.contexa.contexacore.autonomous.event;

import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

@Slf4j
public class CompositeLlmAnalysisEventListener implements LlmAnalysisEventListener {

    private final List<LlmAnalysisEventObserver> observers;

    public CompositeLlmAnalysisEventListener(List<LlmAnalysisEventObserver> observers) {
        this.observers = observers != null ? List.copyOf(observers) : List.of();
    }

    @Override
    public void onContextCollected(String userId, String requestPath) {
        observers.forEach(observer -> invoke(() -> observer.onContextCollected(userId, requestPath)));
    }

    @Override
    public void onContextCollected(String userId, String requestPath, Map<String, Object> metadata) {
        observers.forEach(observer -> invoke(() -> observer.onContextCollected(userId, requestPath, metadata)));
    }

    @Override
    public void onLayer1Start(String userId, String requestPath) {
        observers.forEach(observer -> invoke(() -> observer.onLayer1Start(userId, requestPath)));
    }

    @Override
    public void onLayer1Start(String userId, String requestPath, Map<String, Object> metadata) {
        observers.forEach(observer -> invoke(() -> observer.onLayer1Start(userId, requestPath, metadata)));
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs) {
        observers.forEach(observer -> invoke(() -> observer.onLayer1Complete(
                userId,
                action,
                riskScore,
                confidence,
                reasoning,
                mitre,
                elapsedMs,
                Map.of())));
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs, Map<String, Object> metadata) {
        observers.forEach(observer -> invoke(() -> observer.onLayer1Complete(
                userId,
                action,
                riskScore,
                confidence,
                reasoning,
                mitre,
                elapsedMs,
                metadata)));
    }

    @Override
    public void onLayer1Complete(String userId, String action, String reasoning, String mitre, Long elapsedMs) {
        observers.forEach(observer -> invoke(() -> observer.onLayer1Complete(userId, action, reasoning, mitre, elapsedMs)));
    }

    @Override
    public void onLayer1Complete(String userId, String action, String reasoning, String mitre, Long elapsedMs, Map<String, Object> metadata) {
        observers.forEach(observer -> invoke(() -> observer.onLayer1Complete(
                userId,
                action,
                null,
                null,
                reasoning,
                mitre,
                elapsedMs,
                metadata)));
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason) {
        observers.forEach(observer -> invoke(() -> observer.onLayer2Start(userId, requestPath, reason)));
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason, Map<String, Object> metadata) {
        observers.forEach(observer -> invoke(() -> observer.onLayer2Start(userId, requestPath, reason, metadata)));
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs) {
        observers.forEach(observer -> invoke(() -> observer.onLayer2Complete(
                userId,
                action,
                riskScore,
                confidence,
                reasoning,
                mitre,
                elapsedMs,
                Map.of())));
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs, Map<String, Object> metadata) {
        observers.forEach(observer -> invoke(() -> observer.onLayer2Complete(
                userId,
                action,
                riskScore,
                confidence,
                reasoning,
                mitre,
                elapsedMs,
                metadata)));
    }

    @Override
    public void onLayer2Complete(String userId, String action, String reasoning, String mitre, Long elapsedMs) {
        observers.forEach(observer -> invoke(() -> observer.onLayer2Complete(userId, action, reasoning, mitre, elapsedMs)));
    }

    @Override
    public void onLayer2Complete(String userId, String action, String reasoning, String mitre, Long elapsedMs, Map<String, Object> metadata) {
        observers.forEach(observer -> invoke(() -> observer.onLayer2Complete(
                userId,
                action,
                null,
                null,
                reasoning,
                mitre,
                elapsedMs,
                metadata)));
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath) {
        observers.forEach(observer -> invoke(() -> observer.onDecisionApplied(userId, action, layer, requestPath)));
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath, Map<String, Object> metadata) {
        observers.forEach(observer -> invoke(() -> observer.onDecisionApplied(userId, action, layer, requestPath, metadata)));
    }

    @Override
    public void onError(String userId, String message) {
        observers.forEach(observer -> invoke(() -> observer.onError(userId, message)));
    }

    @Override
    public void onError(String userId, String message, Map<String, Object> metadata) {
        observers.forEach(observer -> invoke(() -> observer.onError(userId, message, metadata)));
    }

    @Override
    public void onEscalateProtectionTriggered(String userId, String requestPath, int escalateCount, int totalAnalysisCount) {
        observers.forEach(observer -> invoke(() -> observer.onEscalateProtectionTriggered(userId, requestPath, escalateCount, totalAnalysisCount)));
    }

    @Override
    public void onHcadAnalysis(String userId, Map<String, Object> hcadData) {
        observers.forEach(observer -> invoke(() -> observer.onHcadAnalysis(userId, hcadData)));
    }

    @Override
    public void onSessionContextLoaded(String userId, Map<String, Object> sessionData) {
        observers.forEach(observer -> invoke(() -> observer.onSessionContextLoaded(userId, sessionData)));
    }

    @Override
    public void onRagSearchComplete(String userId, int matchedCount, long ragSearchMs) {
        observers.forEach(observer -> invoke(() -> observer.onRagSearchComplete(userId, matchedCount, ragSearchMs)));
    }

    @Override
    public void onBehaviorAnalysisComplete(String userId, Map<String, Object> behaviorData) {
        observers.forEach(observer -> invoke(() -> observer.onBehaviorAnalysisComplete(userId, behaviorData)));
    }

    @Override
    public void onLlmExecutionStart(String userId, String modelName, long promptBuildMs) {
        observers.forEach(observer -> invoke(() -> observer.onLlmExecutionStart(userId, modelName, promptBuildMs)));
    }

    @Override
    public void onLlmExecutionComplete(String userId, long llmExecutionMs, long responseParseMs) {
        observers.forEach(observer -> invoke(() -> observer.onLlmExecutionComplete(userId, llmExecutionMs, responseParseMs)));
    }

    private void invoke(Runnable runnable) {
        try {
            runnable.run();
        } catch (Exception ex) {
            log.error("Failed to publish LLM analysis observer event", ex);
        }
    }
}
