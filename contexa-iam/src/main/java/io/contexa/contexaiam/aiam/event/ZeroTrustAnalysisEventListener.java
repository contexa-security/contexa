package io.contexa.contexaiam.aiam.event;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import lombok.RequiredArgsConstructor;

/**
 * Decorator for LlmAnalysisEventListener that publishes
 * Zero Trust SSE events for BLOCK/ESCALATE page real-time notifications,
 * while delegating to the existing implementation (e.g., LlmAnalysisEventListenerImpl)
 * to preserve security-test.html SSE functionality.
 *
 * Registered as @Primary via IamAiamZeroTrustSseAutoConfiguration.
 */
@RequiredArgsConstructor
public class ZeroTrustAnalysisEventListener implements LlmAnalysisEventListener {

    private final ZeroTrustSsePublisher ssePublisher;
    private final LlmAnalysisEventListener delegate;

    @Override
    public void onContextCollected(String userId, String requestPath, String analysisRequirement) {
        if (delegate != null) {
            delegate.onContextCollected(userId, requestPath, analysisRequirement);
        }
    }

    @Override
    public void onLayer1Start(String userId, String requestPath) {
        if (delegate != null) {
            delegate.onLayer1Start(userId, requestPath);
        }
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double riskScore,
                                  Double confidence, String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER1", action, riskScore, confidence);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer1Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
        }
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason) {
        if (delegate != null) {
            delegate.onLayer2Start(userId, requestPath, reason);
        }
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double riskScore,
                                  Double confidence, String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER2", action, riskScore, confidence);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer2Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
        }
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.decisionComplete(
                userId, action, layer, requestPath, null, null, null, null);
        ssePublisher.publishDecision(userId, event);

        if (delegate != null) {
            delegate.onDecisionApplied(userId, action, layer, requestPath);
        }
    }

    @Override
    public void onError(String userId, String message) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.error(userId, message);
        ssePublisher.publishError(userId, event);

        if (delegate != null) {
            delegate.onError(userId, message);
        }
    }
}
