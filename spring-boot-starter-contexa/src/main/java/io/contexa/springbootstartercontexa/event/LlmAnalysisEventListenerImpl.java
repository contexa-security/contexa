package io.contexa.springbootstartercontexa.event;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

//@Component
@RequiredArgsConstructor
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
}
