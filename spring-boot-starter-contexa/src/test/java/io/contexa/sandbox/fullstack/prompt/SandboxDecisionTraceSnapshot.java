package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * test-only snapshot that binds prompt input truth and decision-layer outputs by requestId.
 *
 * Purpose:
 * - CDC/ERA/SUHR must evaluate the same request across prompt inputs and final decision outputs.
 * - This snapshot captures the LLM step output, parsed response, and final wrapped response
 *   after PostprocessingStep succeeds.
 */
public record SandboxDecisionTraceSnapshot(
        String requestId,
        Instant capturedAt,
        String boundaryMode,
        String modelId,
        String aiGenerationType,
        String targetResponseType,
        Boolean structuredOutputComplete,
        Object llmRawRequest,
        Object llmRawResponse,
        Object llmExecutionResult,
        Object parsedResponse,
        Object finalResponse,
        String rawSystemPrompt,
        String rawUserPrompt,
        String systemPrompt,
        String userPrompt,
        Map<String, Object> promptMetadata,
        PromptExecutionMetadata promptExecutionMetadata,
        Map<String, Object> pipelineMetadata) {

    public SandboxDecisionTraceSnapshot {
        promptMetadata = promptMetadata == null ? Map.of() : Map.copyOf(promptMetadata);
        pipelineMetadata = pipelineMetadata == null ? Map.of() : Map.copyOf(pipelineMetadata);
    }

    public Map<String, Object> toDiagnosticMap(ObjectMapper objectMapper) {
        Map<String, Object> diagnostic = new LinkedHashMap<>();
        diagnostic.put("requestId", requestId);
        diagnostic.put("capturedAt", capturedAt != null ? capturedAt.toString() : null);
        diagnostic.put("boundaryMode", boundaryMode);
        diagnostic.put("modelId", modelId);
        diagnostic.put("aiGenerationType", aiGenerationType);
        diagnostic.put("targetResponseType", targetResponseType);
        diagnostic.put("structuredOutputComplete", structuredOutputComplete);
        diagnostic.put("llmRawRequest",
                llmRawRequest != null ? objectMapper.convertValue(llmRawRequest, Object.class) : null);
        diagnostic.put("llmRawResponse",
                llmRawResponse != null ? objectMapper.convertValue(llmRawResponse, Object.class) : null);
        diagnostic.put("llmExecutionResult",
                llmExecutionResult != null ? objectMapper.convertValue(llmExecutionResult, Object.class) : null);
        diagnostic.put("parsedResponse",
                parsedResponse != null ? objectMapper.convertValue(parsedResponse, Object.class) : null);
        diagnostic.put("finalResponse",
                finalResponse != null ? objectMapper.convertValue(finalResponse, Object.class) : null);
        diagnostic.put("rawSystemPrompt", rawSystemPrompt);
        diagnostic.put("rawUserPrompt", rawUserPrompt);
        diagnostic.put("systemPrompt", systemPrompt);
        diagnostic.put("userPrompt", userPrompt);
        diagnostic.put("promptMetadata", promptMetadata);
        diagnostic.put("promptExecutionMetadata",
                promptExecutionMetadata != null ? objectMapper.convertValue(promptExecutionMetadata, Map.class) : Map.of());
        diagnostic.put("pipelineMetadata", pipelineMetadata);
        return diagnostic;
    }
}
