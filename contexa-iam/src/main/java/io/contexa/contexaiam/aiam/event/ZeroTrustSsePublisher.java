package io.contexa.contexaiam.aiam.event;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Per-user SSE emitter manager for Zero Trust BLOCK/ESCALATE page notifications.
 */
@Slf4j
public class ZeroTrustSsePublisher {

    private final Map<String, List<SseEmitter>> userEmitters = new ConcurrentHashMap<>();

    private static final long SSE_TIMEOUT = 300_000L;

    /**
     * Register a new SSE emitter for the specified user.
     */
    public SseEmitter addEmitter(String userId) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT);

        List<SseEmitter> emitters = userEmitters.computeIfAbsent(
                userId, k -> new CopyOnWriteArrayList<>());

        emitter.onCompletion(() -> emitters.remove(emitter));
        emitter.onTimeout(() -> emitters.remove(emitter));
        emitter.onError(e -> emitters.remove(emitter));

        emitters.add(emitter);

        try {
            emitter.send(SseEmitter.event()
                    .name("connected")
                    .data("{\"status\":\"connected\",\"userId\":\"" + userId
                            + "\",\"timestamp\":" + System.currentTimeMillis() + "}"));
        } catch (IOException e) {
            log.error("[ZeroTrustSsePublisher] Failed to send connection event: userId={}", userId, e);
        }

        return emitter;
    }

    /**
     * Publish a decision complete event to the specified user.
     */
    public void publishDecision(String userId, ZeroTrustSseEvent event) {
        sendToUser(userId, event);
    }

    /**
     * Publish an analysis progress event to the specified user.
     */
    public void publishAnalysisProgress(String userId, ZeroTrustSseEvent event) {
        sendToUser(userId, event);
    }

    /**
     * Publish an error event to the specified user.
     */
    public void publishError(String userId, ZeroTrustSseEvent event) {
        sendToUser(userId, event);
    }

    private void sendToUser(String userId, ZeroTrustSseEvent event) {
        List<SseEmitter> emitters = userEmitters.get(userId);
        if (emitters == null || emitters.isEmpty()) {
            return;
        }

        String eventData = event.toJson();
        String eventType = event.getType();
        List<SseEmitter> deadEmitters = new CopyOnWriteArrayList<>();

        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event()
                        .name(eventType)
                        .data(eventData));
            } catch (IOException e) {
                deadEmitters.add(emitter);
            }
        }

        emitters.removeAll(deadEmitters);
    }

    /**
     * Get the number of active subscribers for a user.
     */
    public int getSubscriberCount(String userId) {
        List<SseEmitter> emitters = userEmitters.get(userId);
        return emitters != null ? emitters.size() : 0;
    }
}
