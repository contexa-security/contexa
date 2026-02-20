package io.contexa.contexaiam.aiam.event;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Zero Trust SSE event domain model for BLOCK/ESCALATE page real-time notifications.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Slf4j
public class ZeroTrustSseEvent {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static final String ANALYSIS_PROGRESS = "ANALYSIS_PROGRESS";
    public static final String DECISION_COMPLETE = "DECISION_COMPLETE";
    public static final String ERROR = "ERROR";

    @JsonProperty("type")
    private String type;

    @JsonProperty("userId")
    private String userId;

    @JsonProperty("action")
    private String action;

    @JsonProperty("riskScore")
    private Double riskScore;

    @JsonProperty("confidence")
    private Double confidence;

    @JsonProperty("reasoning")
    private String reasoning;

    @JsonProperty("mitre")
    private String mitre;

    @JsonProperty("layer")
    private String layer;

    @JsonProperty("requestPath")
    private String requestPath;

    @JsonProperty("timestamp")
    private Long timestamp;

    /**
     * Serialize this event to JSON string.
     */
    public String toJson() {
        try {
            return objectMapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            log.error("[ZeroTrustSseEvent] JSON serialization failed", e);
            return "{}";
        }
    }

    /**
     * Create an analysis progress event for layer completion.
     */
    public static ZeroTrustSseEvent analysisProgress(String userId, String layer,
            String action, Double riskScore, Double confidence) {
        return ZeroTrustSseEvent.builder()
                .type(ANALYSIS_PROGRESS)
                .userId(userId)
                .layer(layer)
                .action(action)
                .riskScore(riskScore)
                .confidence(confidence)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * Create a decision complete event with full analysis result.
     */
    public static ZeroTrustSseEvent decisionComplete(String userId, String action,
            String layer, String requestPath,
            Double riskScore, Double confidence,
            String reasoning, String mitre) {
        return ZeroTrustSseEvent.builder()
                .type(DECISION_COMPLETE)
                .userId(userId)
                .action(action)
                .layer(layer)
                .requestPath(requestPath)
                .riskScore(riskScore)
                .confidence(confidence)
                .reasoning(reasoning)
                .mitre(mitre)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * Create an error event.
     */
    public static ZeroTrustSseEvent error(String userId, String reasoning) {
        return ZeroTrustSseEvent.builder()
                .type(ERROR)
                .userId(userId)
                .reasoning(reasoning)
                .timestamp(System.currentTimeMillis())
                .build();
    }
}
