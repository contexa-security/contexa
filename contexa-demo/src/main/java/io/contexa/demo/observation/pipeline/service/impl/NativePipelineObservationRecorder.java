package io.contexa.demo.observation.pipeline.service.impl;

import io.contexa.contexacore.std.llm.observation.LlmObservationContext;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.demo.observation.engine.dto.EngineObservation;
import io.contexa.demo.observation.engine.service.EngineObservationSink;
import io.contexa.demo.observation.pipeline.service.PipelineObservationRecorder;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Profile("contexa")
public class NativePipelineObservationRecorder implements PipelineObservationRecorder {

    private static final List<String> FIELDS = List.of(
            "securityDecisionInitialRawOutputHash", "securityDecisionInitialRawOutputLength",
            "securityDecisionInitialParseFailureCategory", "securityDecisionInitialFallbackAction",
            "securityDecisionInitialFallbackReason", "securityDecisionInitialSemanticViolation",
            "securityDecisionInitialProposedAction", "securityDecisionOutputRetryAttempted",
            "securityDecisionOutputRetryReason", "securityDecisionOutputRetrySucceeded",
            "securityDecisionOutputRetryFailureReason", "selectedModelId", "selectedModelProvider",
            "runtimeModelId", "structuredOutputMode", "structuredOutputPolicy", "providerRetryCount");
    private final EngineObservationSink sink;

    public NativePipelineObservationRecorder(EngineObservationSink sink) {
        this.sink = sink;
    }

    @Override
    public void record(LlmObservationContext source, PipelineExecutionContext context, String completion, String failureType) {
        if (source == null || source.requestId() == null || source.eventId() == null
                || source.processingGeneration() == null) {
            return;
        }
        UUID requestId = UUID.fromString(source.requestId());
        if (!requestId.toString().equals(source.requestId())) {
            return;
        }
        Map<String, Object> values = new LinkedHashMap<>();
        for (String key : FIELDS) {
            Object value = context.getMetadata(key, Object.class);
            if (value instanceof String text) {
                values.put(key, text.substring(0, Math.min(text.length(), 512)));
            } else if (value instanceof Number || value instanceof Boolean) {
                values.put(key, value);
            }
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("captureBoundary", "NATIVE_LLM_STEP_TERMINAL_SIGNAL");
        payload.put("source", source);
        payload.put("executionId", context.getExecutionId());
        payload.put("completion", completion);
        payload.put("nativeMetadata", values);
        if (failureType != null) {
            payload.put("failureType", failureType);
        }
        sink.offer(new EngineObservation(UUID.randomUUID(), requestId, "MODEL_EXECUTION", Instant.now(), payload));
    }
}
