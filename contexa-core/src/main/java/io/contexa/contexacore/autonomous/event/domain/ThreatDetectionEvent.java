package io.contexa.contexacore.autonomous.event.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * 위협 탐지 이벤트 도메인 모델
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ThreatDetectionEvent {
    
    @JsonProperty("event_id")
    private String eventId;
    
    @JsonProperty("event_type")
    @Builder.Default
    private String eventType = "THREAT_DETECTION";
    
    @JsonProperty("timestamp")
    private Instant timestamp;
    
    @JsonProperty("threat_id")
    private String threatId;
    
    @JsonProperty("threat_type")
    private String threatType;
    
    @JsonProperty("threat_level")
    private ThreatLevel threatLevel;
    
    @JsonProperty("mitre_attack_id")
    private String mitreAttackId;
    
    @JsonProperty("detection_source")
    private String detectionSource;
    
    @JsonProperty("confidence_score")
    private Double confidenceScore;
    
    @JsonProperty("affected_resources")
    private String[] affectedResources;
    
    @JsonProperty("recommended_actions")
    private String[] recommendedActions;
    
    @JsonProperty("metadata")
    private Map<String, Object> metadata;
    
    public enum ThreatLevel {
        CRITICAL, HIGH, MEDIUM, LOW, INFO
    }
    
    public static class ThreatDetectionEventBuilder {
        public ThreatDetectionEventBuilder() {
            this.eventId = UUID.randomUUID().toString();
            this.timestamp = Instant.now();
        }
    }
}