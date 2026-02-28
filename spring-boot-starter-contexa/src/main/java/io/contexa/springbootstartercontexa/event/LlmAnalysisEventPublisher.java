package io.contexa.springbootstartercontexa.event;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * LLM 분석 이벤트 발행자
 *
 * TIPS 데모용 실시간 LLM 분석 과정을 SSE를 통해 클라이언트에 전송합니다.
 * 사용자별 구독 관리 및 브로드캐스트 기능을 제공합니다.
 *
 * 아키텍처:
 * ColdPathEventProcessor → LlmAnalysisEventPublisher → SseEmitter → Client
 *
 * @author contexa
 * @since TIPS Demo v1.0
 */
//@Component
@Slf4j
public class LlmAnalysisEventPublisher {

    /**
     * 전체 구독자 목록 (브로드캐스트용)
     */
    private final List<SseEmitter> globalEmitters = new CopyOnWriteArrayList<>();

    /**
     * 사용자별 구독자 목록 (개인화된 이벤트 전송용)
     */
    private final Map<String, List<SseEmitter>> userEmitters = new ConcurrentHashMap<>();

    /**
     * SSE 타임아웃 (5분)
     */
    private static final long SSE_TIMEOUT = 300_000L;

    /**
     * 새 구독자 등록 (글로벌)
     *
     * @return SseEmitter 인스턴스
     */
    public SseEmitter addEmitter() {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT);

        emitter.onCompletion(() -> {
            globalEmitters.remove(emitter);
            log.debug("[LlmAnalysisEventPublisher] SSE 연결 완료, 구독자 제거");
        });

        emitter.onTimeout(() -> {
            globalEmitters.remove(emitter);
            log.debug("[LlmAnalysisEventPublisher] SSE 타임아웃, 구독자 제거");
        });

        emitter.onError(e -> {
            globalEmitters.remove(emitter);
            log.debug("[LlmAnalysisEventPublisher] SSE 에러 발생, 구독자 제거: {}", e.getMessage());
        });

        globalEmitters.add(emitter);
        log.info("[LlmAnalysisEventPublisher] 새 SSE 구독자 등록 (전체 구독자: {})", globalEmitters.size());

        // 연결 확인 이벤트 전송
        try {
            emitter.send(SseEmitter.event()
                    .name("connected")
                    .data("{\"status\":\"connected\",\"timestamp\":" + System.currentTimeMillis() + "}"));
        } catch (IOException e) {
            log.warn("[LlmAnalysisEventPublisher] 연결 확인 이벤트 전송 실패", e);
        }

        return emitter;
    }

    /**
     * 사용자별 구독자 등록
     *
     * @param userId 사용자 ID
     * @return SseEmitter 인스턴스
     */
    public SseEmitter addEmitter(String userId) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT);

        List<SseEmitter> userList = userEmitters.computeIfAbsent(userId, k -> new CopyOnWriteArrayList<>());

        emitter.onCompletion(() -> {
            userList.remove(emitter);
            globalEmitters.remove(emitter);
            log.debug("[LlmAnalysisEventPublisher] SSE 연결 완료 (userId: {})", userId);
        });

        emitter.onTimeout(() -> {
            userList.remove(emitter);
            globalEmitters.remove(emitter);
            log.debug("[LlmAnalysisEventPublisher] SSE 타임아웃 (userId: {})", userId);
        });

        emitter.onError(e -> {
            userList.remove(emitter);
            globalEmitters.remove(emitter);
            log.debug("[LlmAnalysisEventPublisher] SSE 에러 (userId: {}): {}", userId, e.getMessage());
        });

        userList.add(emitter);
        globalEmitters.add(emitter);
        log.info("[LlmAnalysisEventPublisher] 새 SSE 구독자 등록 - userId: {}, 전체: {}", userId, globalEmitters.size());

        // 연결 확인 이벤트 전송
        try {
            emitter.send(SseEmitter.event()
                    .name("connected")
                    .data("{\"status\":\"connected\",\"userId\":\"" + userId + "\",\"timestamp\":" + System.currentTimeMillis() + "}"));
        } catch (IOException e) {
            log.warn("[LlmAnalysisEventPublisher] 연결 확인 이벤트 전송 실패 (userId: {})", userId, e);
        }

        return emitter;
    }

    /**
     * 모든 구독자에게 이벤트 브로드캐스트
     *
     * @param event 전송할 이벤트
     */
    public void publishEvent(LlmAnalysisEvent event) {
        if (globalEmitters.isEmpty()) {
            log.debug("[LlmAnalysisEventPublisher] 구독자 없음, 이벤트 전송 생략: {}", event.getType());
            return;
        }

        String eventData = event.toJson();
        String eventType = event.getType();

        List<SseEmitter> deadEmitters = new CopyOnWriteArrayList<>();

        for (SseEmitter emitter : globalEmitters) {
            try {
                emitter.send(SseEmitter.event()
                        .name(eventType)
                        .data(eventData));
            } catch (IOException e) {
                deadEmitters.add(emitter);
                log.debug("[LlmAnalysisEventPublisher] 이벤트 전송 실패, 구독자 제거: {}", e.getMessage());
            }
        }

        // 죽은 구독자 제거
        globalEmitters.removeAll(deadEmitters);

        log.debug("[LlmAnalysisEventPublisher] 이벤트 브로드캐스트 완료 - type: {}, 구독자: {}, 제거: {}",
                eventType, globalEmitters.size(), deadEmitters.size());
    }

    /**
     * 특정 사용자에게만 이벤트 전송
     *
     * @param userId 사용자 ID
     * @param event 전송할 이벤트
     */
    public void publishEventToUser(String userId, LlmAnalysisEvent event) {
        List<SseEmitter> userList = userEmitters.get(userId);

        if (userList == null || userList.isEmpty()) {
            // 사용자별 구독자가 없으면 브로드캐스트로 폴백
            publishEvent(event);
            return;
        }

        String eventData = event.toJson();
        String eventType = event.getType();

        List<SseEmitter> deadEmitters = new CopyOnWriteArrayList<>();

        for (SseEmitter emitter : userList) {
            try {
                emitter.send(SseEmitter.event()
                        .name(eventType)
                        .data(eventData));
            } catch (IOException e) {
                deadEmitters.add(emitter);
            }
        }

        userList.removeAll(deadEmitters);
        globalEmitters.removeAll(deadEmitters);

        log.debug("[LlmAnalysisEventPublisher] 사용자 이벤트 전송 완료 - userId: {}, type: {}", userId, eventType);
    }

    /**
     * 컨텍스트 수집 완료 이벤트 발행
     */
    public void publishContextCollected(String userId, String requestPath, String analysisRequirement) {
        LlmAnalysisEvent event = LlmAnalysisEvent.contextCollected(userId, requestPath, analysisRequirement);
        publishEvent(event);
        log.info("[LlmAnalysisEventPublisher] CONTEXT_COLLECTED - userId: {}, path: {}, requirement: {}",
                userId, requestPath, analysisRequirement);
    }

    /**
     * Layer1 분석 시작 이벤트 발행
     */
    public void publishLayer1Start(String userId, String requestPath) {
        LlmAnalysisEvent event = LlmAnalysisEvent.layer1Start(userId, requestPath);
        publishEvent(event);
        log.info("[LlmAnalysisEventPublisher] LAYER1_START - userId: {}, path: {}", userId, requestPath);
    }

    /**
     * Layer1 분석 완료 이벤트 발행
     */
    public void publishLayer1Complete(String userId, String action, Double riskScore,
            Double confidence, String reasoning, String mitre, Long elapsedMs) {
        LlmAnalysisEvent event = LlmAnalysisEvent.layer1Complete(
                userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
        publishEvent(event);
        log.info("[LlmAnalysisEventPublisher] LAYER1_COMPLETE - userId: {}, action: {}, risk: {}, confidence: {}, elapsed: {}ms",
                userId, action, riskScore, confidence, elapsedMs);
    }

    /**
     * Layer2 에스컬레이션 이벤트 발행
     */
    public void publishLayer2Start(String userId, String requestPath, String reason) {
        LlmAnalysisEvent event = LlmAnalysisEvent.layer2Start(userId, requestPath, reason);
        publishEvent(event);
        log.info("[LlmAnalysisEventPublisher] LAYER2_START - userId: {}, reason: {}", userId, reason);
    }

    /**
     * Layer2 분석 완료 이벤트 발행
     */
    public void publishLayer2Complete(String userId, String action, Double riskScore,
            Double confidence, String reasoning, String mitre, Long elapsedMs) {
        LlmAnalysisEvent event = LlmAnalysisEvent.layer2Complete(
                userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
        publishEvent(event);
        log.info("[LlmAnalysisEventPublisher] LAYER2_COMPLETE - userId: {}, action: {}, risk: {}, confidence: {}, elapsed: {}ms",
                userId, action, riskScore, confidence, elapsedMs);
    }

    /**
     * 최종 결정 적용 이벤트 발행
     */
    public void publishDecisionApplied(String userId, String action, String layer, String requestPath) {
        LlmAnalysisEvent event = LlmAnalysisEvent.decisionApplied(userId, action, layer, requestPath);
        publishEvent(event);
        log.info("[LlmAnalysisEventPublisher] DECISION_APPLIED - userId: {}, action: {}, layer: {}, path: {}",
                userId, action, layer, requestPath);
    }

    /**
     * 에러 이벤트 발행
     */
    public void publishError(String userId, String message) {
        LlmAnalysisEvent event = LlmAnalysisEvent.error(userId, message);
        publishEvent(event);
        log.error("[LlmAnalysisEventPublisher] ERROR - userId: {}, message: {}", userId, message);
    }

    /**
     * 현재 구독자 수 조회
     */
    public int getSubscriberCount() {
        return globalEmitters.size();
    }

    /**
     * 사용자별 구독자 수 조회
     */
    public int getUserSubscriberCount(String userId) {
        List<SseEmitter> userList = userEmitters.get(userId);
        return userList != null ? userList.size() : 0;
    }
}
