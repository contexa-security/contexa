package io.contexa.springbootstartercontexa.event;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
@Slf4j
public class LlmAnalysisEventPublisher {

    private static final long SSE_TIMEOUT = 300_000L;
    private static final int MAX_RECENT_EVENTS = 80;

    private final List<SseEmitter> globalEmitters = new CopyOnWriteArrayList<>();
    private final Map<String, List<SseEmitter>> userEmitters = new ConcurrentHashMap<>();
    private final Deque<LlmAnalysisEvent> globalRecentEvents = new ArrayDeque<>();
    private final Map<String, Deque<LlmAnalysisEvent>> recentEventsByUser = new ConcurrentHashMap<>();

    public SseEmitter addEmitter() {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT);
        registerEmitter(globalEmitters, emitter, null);
        sendConnectedEvent(emitter, null);
        replay(emitter, snapshot(globalRecentEvents));
        return emitter;
    }

    public SseEmitter addEmitter(String userId) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT);
        List<SseEmitter> emitters = userEmitters.computeIfAbsent(userId, ignored -> new CopyOnWriteArrayList<>());
        registerEmitter(emitters, emitter, userId);
        sendConnectedEvent(emitter, userId);
        replay(emitter, getRecentEvents(userId));
        return emitter;
    }

    public void publishEvent(LlmAnalysisEvent event) {
        if (event == null) {
            return;
        }
        cacheEvent(event);

        if (event.getUserId() != null && !event.getUserId().isBlank()) {
            publishToUserEmitters(event.getUserId(), event);
        }
        publishToEmitters(globalEmitters, event);
    }

    public void publishContextCollected(String userId, String requestPath, Map<String, Object> metadata) {
        publishEvent(LlmAnalysisEvent.contextCollected(userId, requestPath, metadata));
    }

    public void publishLayer1Start(String userId, String requestPath, Map<String, Object> metadata) {
        publishEvent(LlmAnalysisEvent.layer1Start(userId, requestPath, metadata));
    }

    public void publishLayer1Complete(
            String userId,
            String action,
            Double riskScore,
            Double confidence,
            String reasoning,
            String mitre,
            Long elapsedMs,
            Map<String, Object> metadata) {
        publishEvent(LlmAnalysisEvent.layer1Complete(
                userId,
                action,
                riskScore,
                confidence,
                reasoning,
                mitre,
                elapsedMs,
                metadata));
    }

    public void publishLayer2Start(String userId, String requestPath, String reason, Map<String, Object> metadata) {
        Map<String, Object> merged = mergeMetadata(metadata);
        if (reason != null) {
            merged.put("escalationReason", reason);
        }
        publishEvent(LlmAnalysisEvent.layer2Start(userId, requestPath, reason, merged));
    }

    public void publishLayer2Complete(
            String userId,
            String action,
            Double riskScore,
            Double confidence,
            String reasoning,
            String mitre,
            Long elapsedMs,
            Map<String, Object> metadata) {
        publishEvent(LlmAnalysisEvent.layer2Complete(
                userId,
                action,
                riskScore,
                confidence,
                reasoning,
                mitre,
                elapsedMs,
                metadata));
    }

    public void publishDecisionApplied(String userId, String action, String layer, String requestPath, Map<String, Object> metadata) {
        publishEvent(LlmAnalysisEvent.decisionApplied(userId, action, layer, requestPath, metadata));
    }

    public void publishResponseBlocked(String userId, long bytesTransferred, String reason, Map<String, Object> metadata) {
        publishEvent(LlmAnalysisEvent.responseBlocked(userId, bytesTransferred, reason, metadata));
    }

    public void publishHcadAnalysis(String userId, Map<String, Object> hcadData) {
        publishEvent(LlmAnalysisEvent.pipeline(
                LlmAnalysisEvent.EventType.HCAD_ANALYSIS,
                userId,
                LlmAnalysisEvent.Status.COMPLETED,
                hcadData,
                null));
    }

    public void publishSessionContextLoaded(String userId, Map<String, Object> sessionData) {
        publishEvent(LlmAnalysisEvent.pipeline(
                LlmAnalysisEvent.EventType.SESSION_CONTEXT_LOADED,
                userId,
                LlmAnalysisEvent.Status.COMPLETED,
                sessionData,
                null));
    }

    public void publishRagSearchComplete(String userId, int matchedCount, long ragSearchMs) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("matchedCount", matchedCount);
        publishEvent(LlmAnalysisEvent.pipeline(
                LlmAnalysisEvent.EventType.RAG_SEARCH_COMPLETE,
                userId,
                LlmAnalysisEvent.Status.COMPLETED,
                metadata,
                ragSearchMs));
    }

    public void publishBehaviorAnalysisComplete(String userId, Map<String, Object> behaviorData) {
        publishEvent(LlmAnalysisEvent.pipeline(
                LlmAnalysisEvent.EventType.BEHAVIOR_ANALYSIS_COMPLETE,
                userId,
                LlmAnalysisEvent.Status.COMPLETED,
                behaviorData,
                null));
    }

    public void publishLlmExecutionStart(String userId, String modelName, long promptBuildMs) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("modelName", modelName);
        publishEvent(LlmAnalysisEvent.pipeline(
                LlmAnalysisEvent.EventType.LLM_EXECUTION_START,
                userId,
                LlmAnalysisEvent.Status.IN_PROGRESS,
                metadata,
                promptBuildMs));
    }

    public void publishLlmExecutionComplete(String userId, long llmExecutionMs, long responseParseMs) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("responseParseMs", responseParseMs);
        publishEvent(LlmAnalysisEvent.pipeline(
                LlmAnalysisEvent.EventType.LLM_EXECUTION_COMPLETE,
                userId,
                LlmAnalysisEvent.Status.COMPLETED,
                metadata,
                llmExecutionMs));
    }

    public void publishError(String userId, String message, Map<String, Object> metadata) {
        publishEvent(LlmAnalysisEvent.error(userId, message, metadata));
    }

    public int getSubscriberCount() {
        return globalEmitters.size();
    }

    public int getUserSubscriberCount(String userId) {
        List<SseEmitter> emitters = userEmitters.get(userId);
        return emitters != null ? emitters.size() : 0;
    }

    public List<LlmAnalysisEvent> getRecentEvents(String userId) {
        Deque<LlmAnalysisEvent> queue = recentEventsByUser.get(userId);
        if (queue == null) {
            return List.of();
        }
        synchronized (queue) {
            return List.copyOf(queue);
        }
    }

    private void registerEmitter(List<SseEmitter> registry, SseEmitter emitter, String userId) {
        emitter.onCompletion(() -> removeEmitter(registry, emitter, userId));
        emitter.onTimeout(() -> removeEmitter(registry, emitter, userId));
        emitter.onError(ex -> removeEmitter(registry, emitter, userId));
        registry.add(emitter);
    }

    private void removeEmitter(List<SseEmitter> registry, SseEmitter emitter, String userId) {
        registry.remove(emitter);
        if (userId != null) {
            List<SseEmitter> emitters = userEmitters.get(userId);
            if (emitters != null) {
                emitters.remove(emitter);
                if (emitters.isEmpty()) {
                    userEmitters.remove(userId);
                }
            }
        }
    }

    private void sendConnectedEvent(SseEmitter emitter, String userId) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("status", "connected");
        payload.put("timestamp", System.currentTimeMillis());
        if (userId != null) {
            payload.put("userId", userId);
        }
        try {
            emitter.send(SseEmitter.event().name("connected").data(payload));
        } catch (IOException e) {
            log.debug("[LlmAnalysisEventPublisher] failed to send connected event", e);
        }
    }

    private void replay(SseEmitter emitter, List<LlmAnalysisEvent> events) {
        for (LlmAnalysisEvent event : events) {
            try {
                emitter.send(SseEmitter.event().name(event.getType()).data(event.toJson()));
            } catch (IOException e) {
                log.debug("[LlmAnalysisEventPublisher] replay failed: {}", e.getMessage());
                break;
            }
        }
    }

    private void publishToUserEmitters(String userId, LlmAnalysisEvent event) {
        List<SseEmitter> emitters = userEmitters.get(userId);
        if (emitters == null || emitters.isEmpty()) {
            return;
        }
        publishToEmitters(emitters, event);
    }

    private void publishToEmitters(List<SseEmitter> emitters, LlmAnalysisEvent event) {
        if (emitters == null || emitters.isEmpty()) {
            return;
        }
        List<SseEmitter> deadEmitters = new ArrayList<>();
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event().name(event.getType()).data(event.toJson()));
            } catch (IOException e) {
                deadEmitters.add(emitter);
            }
        }
        emitters.removeAll(deadEmitters);
    }

    private void cacheEvent(LlmAnalysisEvent event) {
        append(globalRecentEvents, event);
        if (event.getUserId() != null && !event.getUserId().isBlank()) {
            Deque<LlmAnalysisEvent> userQueue = recentEventsByUser.computeIfAbsent(event.getUserId(), ignored -> new ArrayDeque<>());
            append(userQueue, event);
        }
    }

    private void append(Deque<LlmAnalysisEvent> queue, LlmAnalysisEvent event) {
        synchronized (queue) {
            queue.addLast(event);
            while (queue.size() > MAX_RECENT_EVENTS) {
                queue.removeFirst();
            }
        }
    }

    private List<LlmAnalysisEvent> snapshot(Deque<LlmAnalysisEvent> queue) {
        synchronized (queue) {
            return List.copyOf(queue);
        }
    }

    private Map<String, Object> mergeMetadata(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return new LinkedHashMap<>();
        }
        Map<String, Object> merged = new LinkedHashMap<>();
        metadata.forEach((key, value) -> {
            if (key != null && value != null) {
                merged.put(key, value);
            }
        });
        return merged;
    }
}
