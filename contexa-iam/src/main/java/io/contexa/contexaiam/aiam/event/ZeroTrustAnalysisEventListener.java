package io.contexa.contexaiam.aiam.event;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import lombok.RequiredArgsConstructor;

/**
 * LlmAnalysisEventListener implementation that publishes
 * Zero Trust SSE events for BLOCK/ESCALATE page real-time notifications.
 * Registered via IamAiamZeroTrustSseAutoConfiguration,
 * overriding the default no-op in CoreAutonomousEventAutoConfiguration.
 */
@RequiredArgsConstructor
public class ZeroTrustAnalysisEventListener implements LlmAnalysisEventListener {

    private final ZeroTrustSsePublisher ssePublisher;

    @Override
    public void onContextCollected(String userId, String requestPath, String analysisRequirement) {
        // Not relevant for BLOCK/ESCALATE pages
    }

    @Override
    public void onLayer1Start(String userId, String requestPath) {
        // Not relevant for BLOCK/ESCALATE pages
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double riskScore,
                                  Double confidence, String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER1", action, riskScore, confidence);
        ssePublisher.publishAnalysisProgress(userId, event);
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason) {
        // Not relevant for BLOCK/ESCALATE pages
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double riskScore,
                                  Double confidence, String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER2", action, riskScore, confidence);
        ssePublisher.publishAnalysisProgress(userId, event);
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.decisionComplete(
                userId, action, layer, requestPath, null, null, null, null);
        ssePublisher.publishDecision(userId, event);
    }

    @Override
    public void onError(String userId, String message) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.error(userId, message);
        ssePublisher.publishError(userId, event);
    }
}
