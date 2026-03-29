package io.contexa.springbootstartercontexa.event;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.LinkedHashMap;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Slf4j
public class LlmAnalysisEvent {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @JsonProperty("type")
    private String type;

    @JsonProperty("userId")
    private String userId;

    @JsonProperty("requestId")
    private String requestId;

    @JsonProperty("correlationId")
    private String correlationId;

    @JsonProperty("layer")
    private String layer;

    @JsonProperty("status")
    private String status;

    @JsonProperty("action")
    private String action;

    @JsonProperty("riskScore")
    private Double riskScore;

    @JsonProperty("confidence")
    private Double confidence;

    @JsonProperty("reasoning")
    private String reasoning;

    @JsonProperty("reasoningSummary")
    private String reasoningSummary;

    @JsonProperty("mitre")
    private String mitre;

    @JsonProperty("timestamp")
    private Long timestamp;

    @JsonProperty("elapsedMs")
    private Long elapsedMs;

    @JsonProperty("requestPath")
    private String requestPath;

    @JsonProperty("analysisRequirement")
    private String analysisRequirement;

    @JsonProperty("clientIp")
    private String clientIp;

    @JsonProperty("userAgent")
    private String userAgent;

    @JsonProperty("contextBindingHash")
    private String contextBindingHash;

    @JsonProperty("scenario")
    private String scenario;

    @JsonProperty("metadata")
    private Map<String, Object> metadata;

    public String toJson() {
        try {
            return OBJECT_MAPPER.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            log.error("[LlmAnalysisEvent] JSON serialization failed", e);
            return "{}";
        }
    }

    public static class EventType {
        public static final String CONTEXT_COLLECTED = "CONTEXT_COLLECTED";
        public static final String LAYER1_START = "LAYER1_START";
        public static final String LAYER1_COMPLETE = "LAYER1_COMPLETE";
        public static final String LAYER2_START = "LAYER2_START";
        public static final String LAYER2_COMPLETE = "LAYER2_COMPLETE";
        public static final String DECISION_APPLIED = "DECISION_APPLIED";
        public static final String RESPONSE_BLOCKED = "RESPONSE_BLOCKED";
        public static final String ERROR = "ERROR";
        public static final String HCAD_ANALYSIS = "HCAD_ANALYSIS";
        public static final String SESSION_CONTEXT_LOADED = "SESSION_CONTEXT_LOADED";
        public static final String RAG_SEARCH_COMPLETE = "RAG_SEARCH_COMPLETE";
        public static final String BEHAVIOR_ANALYSIS_COMPLETE = "BEHAVIOR_ANALYSIS_COMPLETE";
        public static final String LLM_EXECUTION_START = "LLM_EXECUTION_START";
        public static final String LLM_EXECUTION_COMPLETE = "LLM_EXECUTION_COMPLETE";
    }

    public static class Status {
        public static final String IN_PROGRESS = "IN_PROGRESS";
        public static final String COMPLETED = "COMPLETED";
        public static final String ESCALATED = "ESCALATED";
        public static final String ERROR = "ERROR";
    }

    public static class Layer {
        public static final String LAYER1 = "LAYER1";
        public static final String LAYER2 = "LAYER2";
        public static final String PIPELINE = "PIPELINE";
    }

    public static LlmAnalysisEvent contextCollected(
            String userId,
            String requestPath,
            String analysisRequirement,
            Map<String, Object> metadata) {
        return baseBuilder(userId, metadata)
                .type(EventType.CONTEXT_COLLECTED)
                .requestPath(requestPath)
                .analysisRequirement(analysisRequirement)
                .status(Status.COMPLETED)
                .build();
    }

    public static LlmAnalysisEvent layer1Start(String userId, String requestPath, Map<String, Object> metadata) {
        return baseBuilder(userId, metadata)
                .type(EventType.LAYER1_START)
                .requestPath(requestPath)
                .layer(Layer.LAYER1)
                .status(Status.IN_PROGRESS)
                .build();
    }

    public static LlmAnalysisEvent layer1Complete(
            String userId,
            String action,
            Double riskScore,
            Double confidence,
            String reasoning,
            String mitre,
            Long elapsedMs,
            Map<String, Object> metadata) {
        return baseBuilder(userId, metadata)
                .type(EventType.LAYER1_COMPLETE)
                .layer(Layer.LAYER1)
                .status(Status.COMPLETED)
                .action(action)
                .riskScore(riskScore)
                .confidence(confidence)
                .reasoning(reasoning)
                .reasoningSummary(summarize(reasoning))
                .mitre(mitre)
                .elapsedMs(elapsedMs)
                .build();
    }

    public static LlmAnalysisEvent layer2Start(String userId, String requestPath, String reason, Map<String, Object> metadata) {
        return baseBuilder(userId, metadata)
                .type(EventType.LAYER2_START)
                .requestPath(requestPath)
                .layer(Layer.LAYER2)
                .status(Status.IN_PROGRESS)
                .reasoning(reason)
                .reasoningSummary(summarize(reason))
                .build();
    }

    public static LlmAnalysisEvent layer2Complete(
            String userId,
            String action,
            Double riskScore,
            Double confidence,
            String reasoning,
            String mitre,
            Long elapsedMs,
            Map<String, Object> metadata) {
        return baseBuilder(userId, metadata)
                .type(EventType.LAYER2_COMPLETE)
                .layer(Layer.LAYER2)
                .status(Status.COMPLETED)
                .action(action)
                .riskScore(riskScore)
                .confidence(confidence)
                .reasoning(reasoning)
                .reasoningSummary(summarize(reasoning))
                .mitre(mitre)
                .elapsedMs(elapsedMs)
                .build();
    }

    public static LlmAnalysisEvent decisionApplied(
            String userId,
            String action,
            String layer,
            String requestPath,
            Map<String, Object> metadata) {
        return baseBuilder(userId, metadata)
                .type(EventType.DECISION_APPLIED)
                .action(action)
                .layer(layer)
                .requestPath(requestPath)
                .status(Status.COMPLETED)
                .build();
    }

    public static LlmAnalysisEvent responseBlocked(
            String userId,
            long bytesTransferred,
            String reason,
            Map<String, Object> metadata) {
        Map<String, Object> merged = mergeMetadata(metadata);
        merged.put("bytesTransferred", bytesTransferred);
        return baseBuilder(userId, merged)
                .type(EventType.RESPONSE_BLOCKED)
                .status(Status.COMPLETED)
                .action("BLOCK")
                .reasoning(reason)
                .reasoningSummary(summarize(reason))
                .build();
    }

    public static LlmAnalysisEvent error(String userId, String message, Map<String, Object> metadata) {
        return baseBuilder(userId, metadata)
                .type(EventType.ERROR)
                .status(Status.ERROR)
                .reasoning(message)
                .reasoningSummary(summarize(message))
                .build();
    }

    public static LlmAnalysisEvent pipeline(
            String type,
            String userId,
            String status,
            Map<String, Object> metadata,
            Long elapsedMs) {
        return baseBuilder(userId, metadata)
                .type(type)
                .layer(Layer.PIPELINE)
                .status(status)
                .elapsedMs(elapsedMs)
                .build();
    }

    private static LlmAnalysisEventBuilder baseBuilder(String userId, Map<String, Object> metadata) {
        Map<String, Object> normalized = mergeMetadata(metadata);
        return LlmAnalysisEvent.builder()
                .userId(userId)
                .requestId(text(normalized, "requestId"))
                .correlationId(text(normalized, "correlationId"))
                .requestPath(text(normalized, "requestPath"))
                .analysisRequirement(text(normalized, "analysisRequirement"))
                .clientIp(text(normalized, "clientIp"))
                .userAgent(text(normalized, "userAgent"))
                .contextBindingHash(text(normalized, "contextBindingHash"))
                .scenario(text(normalized, "scenario"))
                .metadata(normalized.isEmpty() ? null : normalized)
                .timestamp(System.currentTimeMillis());
    }

    private static String summarize(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.replaceAll("\\s+", " ").trim();
        if (normalized.isBlank()) {
            return null;
        }
        return normalized.length() > 280 ? normalized.substring(0, 280) : normalized;
    }

    private static Map<String, Object> mergeMetadata(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> merged = new LinkedHashMap<>();
        metadata.forEach((key, value) -> {
            if (key != null && value != null) {
                merged.put(key, value);
            }
        });
        return Map.copyOf(merged);
    }

    private static String text(Map<String, Object> metadata, String key) {
        Object value = metadata.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isBlank() ? null : text;
    }
}
