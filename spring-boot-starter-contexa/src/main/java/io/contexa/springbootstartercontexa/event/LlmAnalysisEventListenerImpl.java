package io.contexa.springbootstartercontexa.event;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * LLM 분석 이벤트 리스너 구현체
 *
 * contexa-core의 ColdPathEventProcessor에서 발생하는 LLM 분석 이벤트를
 * 수신하여 LlmAnalysisEventPublisher를 통해 SSE로 클라이언트에 전송합니다.
 *
 * 아키텍처:
 * ColdPathEventProcessor -> LlmAnalysisEventListener -> LlmAnalysisEventListenerImpl
 *                                                               |
 *                                                               v
 *                                                      LlmAnalysisEventPublisher
 *                                                               |
 *                                                               v
 *                                                         SseEmitter -> Client
 *
 * @author contexa
 * @since TIPS Demo v1.0
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class LlmAnalysisEventListenerImpl implements LlmAnalysisEventListener {

    private final LlmAnalysisEventPublisher eventPublisher;

    @Override
    public void onContextCollected(String userId, String requestPath, String analysisRequirement) {
        log.debug("[LlmAnalysisEventListenerImpl] CONTEXT_COLLECTED - userId: {}, path: {}, requirement: {}",
                userId, requestPath, analysisRequirement);
        eventPublisher.publishContextCollected(userId, requestPath, analysisRequirement);
    }

    @Override
    public void onLayer1Start(String userId, String requestPath) {
        log.debug("[LlmAnalysisEventListenerImpl] LAYER1_START - userId: {}, path: {}", userId, requestPath);
        eventPublisher.publishLayer1Start(userId, requestPath);
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double riskScore,
                                  Double confidence, String reasoning, String mitre, Long elapsedMs) {
        log.debug("[LlmAnalysisEventListenerImpl] LAYER1_COMPLETE - userId: {}, action: {}, risk: {}, confidence: {}",
                userId, action, riskScore, confidence);
        eventPublisher.publishLayer1Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason) {
        log.debug("[LlmAnalysisEventListenerImpl] LAYER2_START - userId: {}, path: {}, reason: {}",
                userId, requestPath, reason);
        eventPublisher.publishLayer2Start(userId, requestPath, reason);
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double riskScore,
                                  Double confidence, String reasoning, String mitre, Long elapsedMs) {
        log.debug("[LlmAnalysisEventListenerImpl] LAYER2_COMPLETE - userId: {}, action: {}, risk: {}, confidence: {}",
                userId, action, riskScore, confidence);
        eventPublisher.publishLayer2Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath) {
        log.debug("[LlmAnalysisEventListenerImpl] DECISION_APPLIED - userId: {}, action: {}, layer: {}, path: {}",
                userId, action, layer, requestPath);
        eventPublisher.publishDecisionApplied(userId, action, layer, requestPath);
    }

    @Override
    public void onError(String userId, String message) {
        log.debug("[LlmAnalysisEventListenerImpl] ERROR - userId: {}, message: {}", userId, message);
        eventPublisher.publishError(userId, message);
    }
}
