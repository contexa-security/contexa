package io.contexa.contexacore.autonomous.event;

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
}
