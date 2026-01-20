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
public class AuditEvent {
    
    @JsonProperty("event_id")
    private String eventId;
    
    @JsonProperty("event_type")
    @Builder.Default
    private String eventType = "AUDIT_EVENT";
    
    @JsonProperty("timestamp")
    private Instant timestamp;
    
    @JsonProperty("audit_type")
    private String auditType;
    
    @JsonProperty("principal")
    private String principal;
    
    @JsonProperty("action")
    private String action;
    
    @JsonProperty("resource")
    private String resource;
    
    @JsonProperty("result")
    private String result;
    
    @JsonProperty("client_ip")
    private String clientIp;
    
    @JsonProperty("session_id")
    private String sessionId;
    
    @JsonProperty("details")
    private Map<String, Object> details;
    
    public static class AuditEventBuilder {
        public AuditEventBuilder() {
            this.eventId = UUID.randomUUID().toString();
            this.timestamp = Instant.now();
        }
    }
}