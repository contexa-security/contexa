package io.contexa.contexacore.autonomous.event;

import java.util.Map;

public interface LlmAnalysisEventListener {

    void onContextCollected(String userId, String requestPath, String analysisRequirement);

    void onLayer1Start(String userId, String requestPath);

    void onLayer1Complete(String userId, String action, Double riskScore,
                          Double confidence, String reasoning, String mitre, Long elapsedMs);

    void onLayer2Start(String userId, String requestPath, String reason);

    void onLayer2Complete(String userId, String action, Double riskScore,
                          Double confidence, String reasoning, String mitre, Long elapsedMs);

    void onDecisionApplied(String userId, String action, String layer, String requestPath);

    void onError(String userId, String message);

    public void onLayer2Complete(String userId, String action, String reasoning, String mitre, Long elapsedMs);
    public void onEscalateProtectionTriggered(String userId, String requestPath, int escalateCount, int totalAnalysisCount);
    public void onLayer1Complete(String userId, String action, String reasoning, String mitre, Long elapsedMs);

    // Detailed pipeline events (default methods for backward compatibility)
    default void onHcadAnalysis(String userId, Map<String, Object> hcadData) {}
    default void onSessionContextLoaded(String userId, Map<String, Object> sessionData) {}
    default void onRagSearchComplete(String userId, int matchedCount, long ragSearchMs) {}
    default void onBehaviorAnalysisComplete(String userId, Map<String, Object> behaviorData) {}
    default void onLlmExecutionStart(String userId, String modelName, long promptBuildMs) {}
    default void onLlmExecutionComplete(String userId, long llmExecutionMs, long responseParseMs) {}
}
