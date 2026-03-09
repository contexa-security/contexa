package io.contexa.contexacore.autonomous.audit;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.enums.AuditEventCategory;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Immutable audit record DTO based on 5W1H principle.
 * Who, When, Where, What, How, Why - all captured in a single record.
 */
@Getter
@Builder
public class AuditRecord {

    // WHO - who performed the action
    private final String principalName;
    private final String eventSource;

    // WHEN - when did it happen
    @Builder.Default
    private final LocalDateTime timestamp = LocalDateTime.now();

    // WHERE - where was the access from
    private final String clientIp;
    private final String sessionId;
    private final String userAgent;

    // WHAT - what was accessed
    private final String resourceIdentifier;
    private final String resourceUri;
    private final String requestUri;

    // HOW - how was the action performed
    private final String action;
    private final String httpMethod;
    private final AuditEventCategory eventCategory;

    // WHY - why was this decision made
    private final String decision;
    private final String reason;
    private final String outcome;
    private final Double riskScore;
    private final Map<String, Object> details;

    // Tracing
    private final String correlationId;

    /**
     * Convert this record to a persistent AuditLog entity.
     */
    public AuditLog toAuditLog(String detailsJson) {
        return AuditLog.builder()
                .timestamp(timestamp)
                .principalName(principalName != null ? principalName : "UNKNOWN")
                .resourceIdentifier(resourceIdentifier != null ? resourceIdentifier : "UNKNOWN")
                .action(action)
                .decision(decision != null ? decision : "UNKNOWN")
                .reason(truncate(reason, 1024))
                .outcome(outcome)
                .resourceUri(resourceUri)
                .clientIp(clientIp)
                .sessionId(sessionId)
                .details(detailsJson)
                .eventCategory(eventCategory != null ? eventCategory.name() : null)
                .userAgent(truncate(userAgent, 512))
                .httpMethod(httpMethod)
                .requestUri(truncate(requestUri, 2048))
                .riskScore(riskScore)
                .eventSource(eventSource)
                .correlationId(correlationId)
                .build();
    }

    private static String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }
}
