package io.contexa.demo.platform.observation;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventObserver;
import io.contexa.contexacore.util.SensitiveValueSanitizer;
import io.contexa.demo.observation.engine.dto.EngineObservation;
import io.contexa.demo.observation.engine.service.EngineObservationSink;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
@Profile("contexa")
public class NativeAnalysisObserver implements LlmAnalysisEventObserver {

    private static final List<String> SOURCE_FIELDS = List.of("eventId", "requestId", "correlationId",
            "eventProcessingIdentity", "eventProcessingOwnerToken", "requestPath", "resourceId",
            "decisionBoundaryMode", "runtimeEnforcementMode", "llmDecisionPresent", "rawExecutionSucceeded",
            "selectedModelId", "selectedModelProvider", "technicalFallbackApplied", "failureType");
    private final EngineObservationSink sink;

    public NativeAnalysisObserver(EngineObservationSink sink) {
        this.sink = sink;
    }

    @Override
    public void onContextCollected(String userId, String path, Map<String, Object> metadata) {
        capture("CONTEXT_COLLECTED", metadata, Map.of());
    }

    @Override
    public void onLayer1Start(String userId, String path, Map<String, Object> metadata) {
        capture("LAYER1_START", metadata, Map.of());
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double risk, Double confidence, String reasoning,
            String mitre, Long elapsed, Map<String, Object> metadata) {
        capture("LAYER1_CANDIDATE", metadata, candidate(action, risk, confidence, reasoning, elapsed));
    }

    @Override
    public void onLayer2Start(String userId, String path, String reason, Map<String, Object> metadata) {
        capture("LAYER2_START", metadata, Map.of());
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double risk, Double confidence, String reasoning,
            String mitre, Long elapsed, Map<String, Object> metadata) {
        capture("LAYER2_CANDIDATE", metadata, candidate(action, risk, confidence, reasoning, elapsed));
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String path, Map<String, Object> metadata) {
        Map<String, Object> values = candidate(action, null, null, null, null);
        if (layer != null) {
            values.put("layer", layer);
        }
        capture("CANDIDATE_CALLBACK", metadata, values);
    }

    @Override
    public void onError(String userId, String message, Map<String, Object> metadata) {
        capture("ANALYSIS_ERROR", metadata, candidate(null, null, null, message, null));
    }

    private Map<String, Object> candidate(String action, Double risk, Double confidence, String reasoning, Long elapsed) {
        Map<String, Object> values = new LinkedHashMap<>();
        if (action != null) {
            values.put("action", action);
        }
        if (risk != null) {
            values.put("riskScore", risk);
        }
        if (confidence != null) {
            values.put("confidence", confidence);
        }
        if (reasoning != null) {
            String safe = SensitiveValueSanitizer.sanitizeText(reasoning);
            values.put("reasoningSanitized", safe.substring(0, Math.min(safe.length(), 16000)));
        }
        if (elapsed != null) {
            values.put("elapsedMs", elapsed);
        }
        return values;
    }

    private void capture(String kind, Map<String, Object> metadata, Map<String, Object> values) {
        if (metadata == null || metadata.get("requestId") == null) {
            return;
        }
        UUID requestId;
        try {
            requestId = UUID.fromString(metadata.get("requestId").toString());
        } catch (IllegalArgumentException unsupportedId) {
            return;
        }
        Map<String, Object> payload = new LinkedHashMap<>(values);
        for (String field : SOURCE_FIELDS) {
            Object value = metadata.get(field);
            if (value instanceof String text) {
                payload.put(field, text.substring(0, Math.min(text.length(), 1000)));
            } else if (value instanceof Number || value instanceof Boolean) {
                payload.put(field, value);
            }
        }
        sink.offer(new EngineObservation(UUID.randomUUID(), requestId, kind, Instant.now(), payload));
    }
}
