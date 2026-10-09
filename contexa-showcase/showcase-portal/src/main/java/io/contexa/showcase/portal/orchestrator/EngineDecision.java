package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.work.BusinessOperation;

import java.io.IOException;
import java.time.Instant;

/**
 * Control D's decision of one step, read from the engine's final decision record, the analysis events and the
 * measured model calls (deck p.24: engine decision and its grounds, time of application).
 *
 * @param technicalFallback the engine applied a technical fallback (its technical_fallback flag)
 * @param parserFailure     the model response broke the decision contract and the engine fell back
 * @param applied BEFORE_RESPONSE for a synchronous decision, NEXT_REQUEST for an asynchronous one, NONE when the
 *                engine produced no record for the step (an earlier decision still applied, or no analysis)
 */
public record EngineDecision(String finalAction, String proposedAction, Double riskScore, Double confidence,
                             Boolean technicalFallback, Boolean parserFailure, Boolean success, String failureType,
                             String fallbackCategory,
                             String reasoning, String mitre, String applied, Long totalAnalysisMs, Long llmLatencyMs,
                             long promptTokens, long completionTokens, long totalTokens, int modelCalls,
                             Instant decidedAt, JsonNode raw) {

    private static final ObjectMapper METADATA_READER = new ObjectMapper();

    /**
     * Whether control D decides an operation before it answers: the operations its business service marks
     * {@code @Protectable(sync = true)} (ContexaBusinessOperations). Every other protected operation is decided after
     * the answer and applies from the next request.
     */
    public static boolean synchronous(BusinessOperation operation) {
        return operation == BusinessOperation.EXPORT || operation == BusinessOperation.ROLE_GRANT;
    }

    public static EngineDecision none(JsonNode raw) {
        return new EngineDecision(null, null, null, null, null, null, null, null, null, null, null, "NONE", null, null,
                0, 0, 0, 0, null, raw);
    }

    /** Builds the decision from the D management API answer; null when it has no decision record yet. */
    public static EngineDecision from(JsonNode evidence, boolean synchronous) {
        JsonNode records = evidence.path("records");
        if (!records.isArray() || records.isEmpty()) {
            return null;
        }
        JsonNode last = records.get(0);
        long prompt = 0;
        long completion = 0;
        long total = 0;
        int calls = 0;
        for (JsonNode call : evidence.path("modelCalls")) {
            prompt += call.path("promptTokens").asLong(0);
            completion += call.path("completionTokens").asLong(0);
            total += call.path("totalTokens").asLong(0);
            calls++;
        }
        String mitre = null;
        for (JsonNode event : evidence.path("events")) {
            if (event.hasNonNull("mitre")) {
                mitre = event.path("mitre").asText();
            }
        }
        String decidedAt = text(last, "decidedAt");
        return new EngineDecision(text(last, "finalAction"), text(last, "proposedAction"), number(last, "riskScore"),
                number(last, "confidence"), last.path("technicalFallback").asBoolean(false),
                last.path("parserFailure").asBoolean(false), last.path("success").asBoolean(false), text(last, "failureType"), text(last, "fallbackCategory"),
                reasoning(last), mitre, synchronous ? "BEFORE_RESPONSE" : "NEXT_REQUEST",
                longOrNull(last, "totalAnalysisMs"), longOrNull(last, "llmLatencyMs"), prompt, completion, total, calls,
                decidedAt == null ? null : Instant.parse(decidedAt), evidence);
    }

    /**
     * The engine produced no real decision: the analysis failed, the response broke the contract (parser failure)
     * or a technical fallback was applied. Counted apart, never as a decision (deck p.24).
     */
    public boolean unresolved() {
        return finalAction != null && (Boolean.TRUE.equals(technicalFallback) || Boolean.TRUE.equals(parserFailure)
                || !Boolean.TRUE.equals(success));
    }

    private static String reasoning(JsonNode record) {
        String metadata = text(record, "metadataJson");
        if (metadata == null) {
            return null;
        }
        try {
            JsonNode parsed = METADATA_READER.readTree(metadata);
            JsonNode value = parsed.path("finalDecisionReasoning");
            return value.isMissingNode() || value.isNull() ? null : value.asText();
        } catch (IOException e) {
            return null;
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static Double number(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asDouble();
    }

    private static Long longOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asLong();
    }
}
