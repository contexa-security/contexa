package io.contexa.contexaiam.aiam.event;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import lombok.RequiredArgsConstructor;

import java.util.Map;

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
    public void onContextCollected(String userId, String requestPath) {
        if (delegate != null) {
            delegate.onContextCollected(userId, requestPath);
        }
    }

    @Override
    public void onContextCollected(String userId, String requestPath, Map<String, Object> metadata) {
        if (delegate != null) {
            delegate.onContextCollected(userId, requestPath, metadata);
        }
    }

    @Override
    public void onLayer1Start(String userId, String requestPath) {
        if (delegate != null) {
            delegate.onLayer1Start(userId, requestPath);
        }
    }

    @Override
    public void onLayer1Start(String userId, String requestPath, Map<String, Object> metadata) {
        if (delegate != null) {
            delegate.onLayer1Start(userId, requestPath, metadata);
        }
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER1", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer1Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
        }
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs, Map<String, Object> metadata) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER1", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer1Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs, metadata);
        }
    }

    @Override
    public void onLayer1Complete(String userId, String action,
                                  String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER1", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer1Complete(userId, action, reasoning, mitre, elapsedMs);
        }
    }

    @Override
    public void onHcadAnalysis(String userId, Map<String, Object> hcadData) {
        LlmAnalysisEventListener.super.onHcadAnalysis(userId, hcadData);
    }

    @Override
    public void onSessionContextLoaded(String userId, Map<String, Object> sessionData) {
        LlmAnalysisEventListener.super.onSessionContextLoaded(userId, sessionData);
    }

    @Override
    public void onRagSearchComplete(String userId, int matchedCount, long ragSearchMs) {
        LlmAnalysisEventListener.super.onRagSearchComplete(userId, matchedCount, ragSearchMs);
    }

    @Override
    public void onBehaviorAnalysisComplete(String userId, Map<String, Object> behaviorData) {
        LlmAnalysisEventListener.super.onBehaviorAnalysisComplete(userId, behaviorData);
    }

    @Override
    public void onLlmExecutionStart(String userId, String modelName, long promptBuildMs) {
        LlmAnalysisEventListener.super.onLlmExecutionStart(userId, modelName, promptBuildMs);
    }

    @Override
    public void onLlmExecutionComplete(String userId, long llmExecutionMs, long responseParseMs) {
        LlmAnalysisEventListener.super.onLlmExecutionComplete(userId, llmExecutionMs, responseParseMs);
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason) {
        if (delegate != null) {
            delegate.onLayer2Start(userId, requestPath, reason);
        }
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason, Map<String, Object> metadata) {
        if (delegate != null) {
            delegate.onLayer2Start(userId, requestPath, reason, metadata);
        }
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER2", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer2Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
        }
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs, Map<String, Object> metadata) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER2", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer2Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs, metadata);
        }
    }

    @Override
    public void onLayer2Complete(String userId, String action,
                                  String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER2", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer2Complete(userId, action, reasoning, mitre, elapsedMs);
        }
    }

    @Override
    public void onEscalateProtectionTriggered(String userId, String requestPath, int escalateCount, int totalAnalysisCount) {
        if (delegate != null) {
            delegate.onEscalateProtectionTriggered(userId, requestPath, escalateCount, totalAnalysisCount);
        }
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.decisionComplete(
                userId, action, layer, requestPath, null, null);
        ssePublisher.publishDecision(userId, event);

        if (delegate != null) {
            delegate.onDecisionApplied(userId, action, layer, requestPath);
        }
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath, Map<String, Object> metadata) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.decisionComplete(
                userId, action, layer, requestPath, null, null);
        ssePublisher.publishDecision(userId, event);

        if (delegate != null) {
            delegate.onDecisionApplied(userId, action, layer, requestPath, metadata);
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

    @Override
    public void onError(String userId, String message, Map<String, Object> metadata) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.error(userId, message);
        ssePublisher.publishError(userId, event);

        if (delegate != null) {
            delegate.onError(userId, message, metadata);
        }
    }
}
