package io.contexa.contexacore.autonomous.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class SecurityPlaneAuditLogger {

    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper;

    public SecurityPlaneAuditLogger(AuditLogRepository auditLogRepository,
                                   ObjectMapper objectMapper) {
        this.auditLogRepository = auditLogRepository;
        this.objectMapper = objectMapper.copy();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    public void auditSecurityDecision(SecurityEvent event, ProcessingResult result,
                                      long processingTimeMs) {
        try {
            String action = result.getAction();
            String decision = (action != null && !action.isBlank()) ? action.toUpperCase() : "UNANALYZED";
            String reasoning = result.getReasoning();

            AuditLog auditLog = AuditLog.builder()
                .timestamp(LocalDateTime.now())
                .principalName(event.getUserId() != null ? event.getUserId() : "UNKNOWN")
                .resourceIdentifier(event.getEventId())
                .action("SECURITY_DECISION")
                .decision(decision)
                .reason(truncate(reasoning))
                .outcome(result.isSuccess() ? "COMPLETED" : "FAILED")
                .resourceUri(getResourceFromMetadata(event))
                .clientIp(event.getSourceIp())
                .sessionId(event.getSessionId())
                .status(result.isSuccess() ? "COMPLETED" : "FAILED")
                .parameters(createDecisionParams(event, result, processingTimeMs))
                .details(createDecisionDetails(event, result, processingTimeMs))
                .build();

            auditLogRepository.save(auditLog);

        } catch (Exception e) {
            log.error("Failed to audit security decision: eventId={}", event.getEventId(), e);
        }
    }

    public void auditError(String component, String operation, Exception exception,
                         Map<String, Object> errorContext) {
        try {
            String userId = extractString(errorContext, "userId", "SYSTEM");
            String clientIp = extractString(errorContext, "sourceIp", "UNKNOWN");
            String eventId = extractString(errorContext, "eventId", component);

            AuditLog auditLog = AuditLog.builder()
                .timestamp(LocalDateTime.now())
                .principalName(userId)
                .resourceIdentifier(eventId)
                .action("SECURITY_ERROR")
                .decision("ERROR")
                .reason(truncate(exception.getMessage()))
                .outcome(exception.getClass().getSimpleName())
                .resourceUri("/errors/" + component)
                .clientIp(clientIp)
                .status("ERROR")
                .parameters(String.format("component=%s,operation=%s", component, operation))
                .details(createErrorDetails(component, operation, exception, errorContext))
                .build();

            auditLogRepository.save(auditLog);

        } catch (Exception e) {
            log.error("Failed to audit error for component: {}", component, e);
        }
    }

    private String createDecisionParams(SecurityEvent event, ProcessingResult result,
                                        long processingTimeMs) {
        return String.format("decision=%s,riskScore=%.2f,confidence=%.2f,level=%d,time=%dms,severity=%s",
            result.getAction() != null ? result.getAction() : "UNANALYZED",
            result.getRiskScore(),
            result.getConfidence(),
            result.getAiAnalysisLevel(),
            processingTimeMs,
            event.getSeverity() != null ? event.getSeverity() : "MEDIUM");
    }

    private String createDecisionDetails(SecurityEvent event, ProcessingResult result,
                                         long processingTimeMs) {
        Map<String, Object> details = new HashMap<>();

        details.put("eventId", event.getEventId());
        details.put("decision", result.getAction());
        details.put("riskScore", result.getRiskScore());
        details.put("confidence", result.getConfidence());
        details.put("reasoning", result.getReasoning());
        details.put("severity", event.getSeverity() != null ? event.getSeverity().toString() : null);
        details.put("aiAnalysisLevel", result.getAiAnalysisLevel());
        details.put("processingTimeMs", processingTimeMs);
        details.put("threatIndicators", result.getThreatIndicators());
        details.put("recommendedActions", result.getRecommendedActions());
        details.put("sourceIp", event.getSourceIp());
        details.put("userAgent", event.getUserAgent());
        details.put("eventSource", event.getSource() != null ? event.getSource().toString() : null);
        details.put("eventTimestamp", event.getTimestamp() != null ? event.getTimestamp().toString() : null);

        String resourceFromMeta = getResourceFromMetadata(event);
        if (resourceFromMeta != null) {
            details.put("targetResource", resourceFromMeta);
        }

        return toJsonString(details);
    }

    private String createErrorDetails(String component, String operation, Exception exception,
                                    Map<String, Object> errorContext) {
        Map<String, Object> details = new HashMap<>();
        details.put("component", component);
        details.put("operation", operation);
        details.put("errorClass", exception.getClass().getName());
        details.put("errorMessage", exception.getMessage());

        if (errorContext != null) {
            details.put("errorContext", errorContext);
        }

        if (exception.getCause() != null) {
            details.put("cause", exception.getCause().getMessage());
        }

        return toJsonString(details);
    }

    private String toJsonString(Map<String, Object> details) {
        try {
            return objectMapper.writeValueAsString(details);
        } catch (Exception e) {
            log.error("Failed to convert details to JSON", e);
            return details.toString();
        }
    }

    private String getResourceFromMetadata(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return null;
        }
        Object resource = event.getMetadata().get("targetResource");
        return resource != null ? resource.toString() : null;
    }

    private String extractString(Map<String, Object> context, String key, String defaultValue) {
        if (context == null) {
            return defaultValue;
        }
        Object value = context.get(key);
        return (value != null && !value.toString().isBlank()) ? value.toString() : defaultValue;
    }

    private String truncate(String value) {
        if (value == null) {
            return null;
        }
        return value.length() <= 1024 ? value : value.substring(0, 1024);
    }
}
