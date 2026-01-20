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


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SecurityIncidentEvent {
    
    @JsonProperty("event_id")
    private String eventId;
    
    @JsonProperty("event_type")
    @Builder.Default
    private String eventType = "SECURITY_INCIDENT";
    
    @JsonProperty("timestamp")
    private Instant timestamp;
    
    @JsonProperty("incident_id")
    private String incidentId;
    
    @JsonProperty("incident_type")
    private String incidentType;
    
    @JsonProperty("severity")
    private IncidentSeverity severity;
    
    @JsonProperty("source_ip")
    private String sourceIp;
    
    @JsonProperty("target_resource")
    private String targetResource;
    
    @JsonProperty("description")
    private String description;
    
    @JsonProperty("threat_indicators")
    private Map<String, Object> threatIndicators;
    
    @JsonProperty("metadata")
    private Map<String, Object> metadata;
    
    public enum IncidentSeverity {
        CRITICAL, HIGH, MEDIUM, LOW, INFO
    }
    
    public static class SecurityIncidentEventBuilder {
        public SecurityIncidentEventBuilder() {
            this.eventId = UUID.randomUUID().toString();
            this.timestamp = Instant.now();
        }
    }
}