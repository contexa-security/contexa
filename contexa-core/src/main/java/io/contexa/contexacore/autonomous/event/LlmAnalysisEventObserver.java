package io.contexa.contexacore.autonomous.event;

public interface LlmAnalysisEventObserver {

    default void onContextCollected(String userId, String requestPath, String analysisRequirement) {
    }

    default void onLayer1Start(String userId, String requestPath) {
    }

    default void onLayer1Complete(String userId, String action,
                                  String reasoning, String mitre, Long elapsedMs) {
    }

    default void onLayer2Start(String userId, String requestPath, String reason) {
    }

    default void onLayer2Complete(String userId, String action,
                                  String reasoning, String mitre, Long elapsedMs) {
    }

    default void onDecisionApplied(String userId, String action, String layer, String requestPath) {
    }

    default void onError(String userId, String message) {
    }

    default void onEscalateProtectionTriggered(String userId, String requestPath, int escalateCount, int totalAnalysisCount) {
    }
}
