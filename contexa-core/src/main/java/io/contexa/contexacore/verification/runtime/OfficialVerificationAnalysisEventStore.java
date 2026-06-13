package io.contexa.contexacore.verification.runtime;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventObserver;

import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class OfficialVerificationAnalysisEventStore {

    private final Map<String, CopyOnWriteArrayList<AnalysisEvent>> eventsByRequestId = new ConcurrentHashMap<>();

    public void append(AnalysisEvent event) {
        Objects.requireNonNull(event, "event");
        if (event.requestId() == null || event.requestId().isBlank()) {
            return;
        }
        eventsByRequestId.computeIfAbsent(event.requestId(), ignored -> new CopyOnWriteArrayList<>()).add(event);
    }

    public List<AnalysisEvent> findByRequestId(String requestId) {
        return eventsByRequestId.getOrDefault(requestId, new CopyOnWriteArrayList<>()).stream()
                .sorted(Comparator.comparing(AnalysisEvent::observedAt))
                .toList();
    }

    public static class Observer implements LlmAnalysisEventObserver {

        private final OfficialVerificationAnalysisEventStore store;

        public Observer(OfficialVerificationAnalysisEventStore store) {
            this.store = store;
        }

        @Override
        public void onContextCollected(String userId, String requestPath, Map<String, Object> metadata) {
            append(userId, "CONTEXT_COLLECTED", null, "COMPLETED", null, requestPath, null, null, metadata);
        }

        @Override
        public void onLayer1Start(String userId, String requestPath, Map<String, Object> metadata) {
            append(userId, "LAYER1_START", "LAYER1", "IN_PROGRESS", null, requestPath, null, null, metadata);
        }

        @Override
        public void onLayer1Complete(
                String userId,
                String action,
                Double riskScore,
                Double confidence,
                String reasoning,
                String mitre,
                Long elapsedMs,
                Map<String, Object> metadata
        ) {
            Map<String, Object> merged = merge(metadata, riskScore, confidence, mitre);
            append(userId, "LAYER1_COMPLETE", "LAYER1", "COMPLETED", action, text(merged, "requestPath"), reasoning, elapsedMs, merged);
        }

        @Override
        public void onLayer2Start(String userId, String requestPath, String reason, Map<String, Object> metadata) {
            append(userId, "LAYER2_START", "LAYER2", "IN_PROGRESS", null, requestPath, reason, null, metadata);
        }

        @Override
        public void onLayer2Complete(
                String userId,
                String action,
                Double riskScore,
                Double confidence,
                String reasoning,
                String mitre,
                Long elapsedMs,
                Map<String, Object> metadata
        ) {
            Map<String, Object> merged = merge(metadata, riskScore, confidence, mitre);
            append(userId, "LAYER2_COMPLETE", "LAYER2", "COMPLETED", action, text(merged, "requestPath"), reasoning, elapsedMs, merged);
        }

        @Override
        public void onDecisionApplied(String userId, String action, String layer, String requestPath, Map<String, Object> metadata) {
            append(userId, "DECISION_APPLIED", layer, "COMPLETED", action, requestPath, null, null, metadata);
        }

        @Override
        public void onError(String userId, String message, Map<String, Object> metadata) {
            append(userId, "ERROR", null, "ERROR", null, text(metadata, "requestPath"), message, null, metadata);
        }

        @Override
        public void onHcadAnalysis(String userId, Map<String, Object> hcadData) {
            append(userId, "HCAD_ANALYSIS", "PIPELINE", "COMPLETED", null, text(hcadData, "requestPath"), null, null, hcadData);
        }

        @Override
        public void onSessionContextLoaded(String userId, Map<String, Object> sessionData) {
            append(userId, "SESSION_CONTEXT_LOADED", "PIPELINE", "COMPLETED", null, text(sessionData, "requestPath"), null, null, sessionData);
        }

        @Override
        public void onRagSearchComplete(String userId, int matchedCount, long ragSearchMs) {
            append(userId, "RAG_SEARCH_COMPLETE", "PIPELINE", "COMPLETED", null, null, null, ragSearchMs, Map.of("matchedCount", matchedCount));
        }

        @Override
        public void onBehaviorAnalysisComplete(String userId, Map<String, Object> behaviorData) {
            append(userId, "BEHAVIOR_ANALYSIS_COMPLETE", "PIPELINE", "COMPLETED", null, text(behaviorData, "requestPath"), null, null, behaviorData);
        }

        @Override
        public void onLlmExecutionStart(String userId, String modelName, long promptBuildMs) {
            append(userId, "LLM_EXECUTION_START", "PIPELINE", "IN_PROGRESS", null, null, null, promptBuildMs, Map.of("modelName", modelName));
        }

        @Override
        public void onLlmExecutionComplete(String userId, long llmExecutionMs, long responseParseMs) {
            append(userId, "LLM_EXECUTION_COMPLETE", "PIPELINE", "COMPLETED", null, null, null, llmExecutionMs, Map.of("responseParseMs", responseParseMs));
        }

        private void append(
                String userId,
                String type,
                String layer,
                String status,
                String action,
                String requestPath,
                String reasoning,
                Long elapsedMs,
                Map<String, Object> metadata
        ) {
            Map<String, Object> normalized = metadata == null || metadata.isEmpty() ? Map.of() : new LinkedHashMap<>(metadata);
            String requestId = text(normalized, "requestId");
            if (requestId == null || requestId.isBlank()) {
                requestId = text(normalized, "correlationId");
            }
            store.append(new AnalysisEvent(
                    userId,
                    requestId,
                    text(normalized, "correlationId"),
                    type,
                    layer,
                    status,
                    action,
                    requestPath,
                    reasoning,
                    elapsedMs,
                    Instant.now(),
                    Map.copyOf(normalized)
            ));
        }

        private Map<String, Object> merge(Map<String, Object> metadata, Double riskScore, Double confidence, String mitre) {
            Map<String, Object> merged = metadata == null || metadata.isEmpty() ? new LinkedHashMap<>() : new LinkedHashMap<>(metadata);
            if (riskScore != null) {
                merged.put("riskScore", riskScore);
            }
            if (confidence != null) {
                merged.put("confidence", confidence);
            }
            if (mitre != null && !mitre.isBlank()) {
                merged.put("mitre", mitre);
            }
            return merged;
        }

        private String text(Map<String, Object> metadata, String key) {
            if (metadata == null) {
                return null;
            }
            Object value = metadata.get(key);
            if (value == null) {
                return null;
            }
            String normalized = String.valueOf(value).trim();
            return normalized.isBlank() ? null : normalized;
        }
    }

    public record AnalysisEvent(
            String userId,
            String requestId,
            String correlationId,
            String type,
            String layer,
            String status,
            String action,
            String requestPath,
            String reasoning,
            Long elapsedMs,
            Instant observedAt,
            Map<String, Object> metadata) {
    }
}
