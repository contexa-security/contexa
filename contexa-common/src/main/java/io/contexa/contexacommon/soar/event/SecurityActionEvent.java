package io.contexa.contexacommon.soar.event;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;

/**
 * Inter-module security action event DTO.
 * Published via SecurityActionEventPublisher (NoOp in community, Kafka in enterprise).
 * Consumed by enterprise KafkaSecurityActionEventConsumer for SOAR orchestration.
 */
@Data
@Builder
public class SecurityActionEvent implements Serializable {

    private static final long serialVersionUID = 1L;

    private String eventId;
    private ActionType actionType;
    private String userId;
    private String sourceIp;
    private String sessionId;
    private String reason;
    private String triggeredBy;
    @Builder.Default
    private Instant timestamp = Instant.now();
    private Map<String, Object> metadata;

    public enum ActionType {
        IP_BLOCK,
        IP_UNBLOCK,
        SESSION_TERMINATE,
        SESSION_TERMINATE_ALL,
        THREAT_INTEL_ALERT,
        SOAR_AUTO_RESPONSE
    }
}
