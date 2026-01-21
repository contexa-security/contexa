package io.contexa.contexacore.autonomous.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class SecurityPlaneAuditLogger {

    private final AuditLogger baseAuditLogger;
    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper;

    public SecurityPlaneAuditLogger(AuditLogger baseAuditLogger,
                                   AuditLogRepository auditLogRepository,
                                   ObjectMapper objectMapper) {
        this.baseAuditLogger = baseAuditLogger;
        this.auditLogRepository = auditLogRepository;
        this.objectMapper = objectMapper.copy();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    public void auditSecurityEvent(SecurityEvent event, String agentId, String context) {
        try {
            
            String resourceId = getResourceFromMetadata(event);
            AuditLog auditLog = AuditLog.builder()
                .timestamp(LocalDateTime.now())
                .principalName(event.getUserId() != null ? event.getUserId() : "SYSTEM")
                .resourceIdentifier(resourceId != null ? resourceId : event.getEventId())
                .action("SECURITY_EVENT")
                .decision("DETECTED")
                .reason(String.format("Security event detected by %s", agentId))
                .outcome("PROCESSING")
                .resourceUri(resourceId)
                .clientIp(event.getSourceIp())
                .sessionId(event.getSessionId())
                .status(event.getSeverity() != null ? event.getSeverity().toString() : "INFO")
                .parameters(createSecurityEventParams(event))
                .details(createSecurityEventDetails(event, agentId, context))
                .build();

            auditLogRepository.save(auditLog);

        } catch (Exception e) {
            log.error("Failed to audit security event: {}", event.getEventId(), e);
        }
    }

    public void auditThreatAssessment(SecurityEvent event, ThreatAssessment assessment,
                                    String evaluator, String strategy, long processingTimeMs) {
        try {
            
            String action = assessment.getAction() != null ? assessment.getAction() : "ESCALATE";

            AuditLog auditLog = AuditLog.builder()
                .timestamp(LocalDateTime.now())
                .principalName(event.getUserId() != null ? event.getUserId() : "SYSTEM")
                .resourceIdentifier(event.getEventId())
                .action("THREAT_ASSESSMENT")
                .decision(action)  
                .reason(String.format("Evaluated by %s using %s strategy", evaluator, strategy))
                .outcome(String.format("Risk: %.2f, Confidence: %.2f", assessment.getRiskScore(), assessment.getConfidence()))
                .resourceUri(getResourceFromMetadata(event))
                .clientIp(event.getSourceIp())
                .sessionId(event.getSessionId())
                .status(action)  
                .parameters(createThreatAssessmentParams(assessment, evaluator, strategy, processingTimeMs))
                .details(createThreatAssessmentDetails(assessment, evaluator, strategy, processingTimeMs))
                .build();

            auditLogRepository.save(auditLog);

        } catch (Exception e) {
            log.error("Failed to audit threat assessment: {}", assessment.getAssessmentId(), e);
        }
    }

    public void auditProcessingDecision(SecurityEvent event, ProcessingMode mode, String router,
                                      String reason, Map<String, Object> decisionContext) {
        try {
            AuditLog auditLog = AuditLog.builder()
                .timestamp(LocalDateTime.now())
                .principalName(event.getUserId() != null ? event.getUserId() : "SYSTEM")
                .resourceIdentifier(event.getEventId())
                .action("PROCESSING_DECISION")
                .decision(mode.toString())
                .reason(reason)
                .outcome(String.format("Router: %s | Blocking: %s | Escalation: %s",
                    router, mode.isBlocking(), mode.needsEscalation()))
                .resourceUri(getResourceFromMetadata(event))
                .clientIp(event.getSourceIp())
                .sessionId(event.getSessionId())
                .status(mode.isBlocking() ? "BLOCKED" : "ALLOWED")
                .parameters(createProcessingDecisionParams(mode, router))
                .details(createProcessingDecisionDetails(mode, router, reason, decisionContext))
                .build();

            auditLogRepository.save(auditLog);

        } catch (Exception e) {
            log.error("Failed to audit processing decision for event: {}", event.getEventId(), e);
        }
    }

    public void auditAgentStateChange(String agentId, String previousState, String newState,
                                    String reason, Map<String, Object> stateContext) {
        try {
            AuditLog auditLog = AuditLog.builder()
                .timestamp(LocalDateTime.now())
                .principalName("SYSTEM")
                .resourceIdentifier(agentId)
                .action("AGENT_STATE_CHANGE")
                .decision("CHANGED")
                .reason(reason)
                .outcome(String.format("%s -> %s", previousState, newState))
                .resourceUri("/agents/" + agentId)
                .clientIp("INTERNAL")
                .sessionId("SYSTEM")
                .status(newState)
                .parameters(createAgentStateParams(agentId, previousState, newState))
                .details(createAgentStateDetails(agentId, previousState, newState, reason, stateContext))
                .build();

            auditLogRepository.save(auditLog);

        } catch (Exception e) {
            log.error("Failed to audit agent state change: {}", agentId, e);
        }
    }

    public void auditPerformanceMetrics(String component, Map<String, Object> metrics,
                                      long measurementPeriodMs) {
        try {
            AuditLog auditLog = AuditLog.builder()
                .timestamp(LocalDateTime.now())
                .principalName("SYSTEM")
                .resourceIdentifier(component)
                .action("PERFORMANCE_METRICS")
                .decision("COLLECTED")
                .reason("Performance monitoring")
                .outcome(String.format("Period: %dms", measurementPeriodMs))
                .resourceUri("/metrics/" + component)
                .clientIp("INTERNAL")
                .sessionId("SYSTEM")
                .status("INFO")
                .parameters(String.format("period=%dms", measurementPeriodMs))
                .details(createPerformanceMetricsDetails(component, metrics, measurementPeriodMs))
                .build();

            auditLogRepository.save(auditLog);

        } catch (Exception e) {
            log.error("Failed to audit performance metrics for component: {}", component, e);
        }
    }

    public void auditError(String component, String operation, Exception exception,
                         Map<String, Object> errorContext) {
        try {
            AuditLog auditLog = AuditLog.builder()
                .timestamp(LocalDateTime.now())
                .principalName("SYSTEM")
                .resourceIdentifier(component)
                .action("ERROR")
                .decision("FAILED")
                .reason(exception.getMessage())
                .outcome(exception.getClass().getSimpleName())
                .resourceUri("/errors/" + component)
                .clientIp("INTERNAL")
                .sessionId("SYSTEM")
                .status("ERROR")
                .parameters(String.format("operation=%s,error=%s", operation, exception.getClass().getSimpleName()))
                .details(createErrorDetails(component, operation, exception, errorContext))
                .build();

            auditLogRepository.save(auditLog);

            log.error("[ERROR_AUDIT] Component: {} | Operation: {} | Error: {}",
                component, operation, exception.getMessage());

        } catch (Exception e) {
            log.error("Failed to audit error for component: {}", component, e);
        }
    }

    private String createSecurityEventParams(SecurityEvent event) {
        
        return String.format("severity=%s,source=%s,userId=%s",
            event.getSeverity() != null ? event.getSeverity() : "INFO",
            event.getSource() != null ? event.getSource() : "UNKNOWN",
            event.getUserId() != null ? event.getUserId() : "unknown");
    }

    private String createSecurityEventDetails(SecurityEvent event, String agentId, String context) {
        Map<String, Object> details = new HashMap<>();
        
        details.put("auditType", "SECURITY_EVENT");
        details.put("eventId", event.getEventId());
        details.put("severity", event.getSeverity() != null ? event.getSeverity().toString() : "INFO");
        details.put("agentId", agentId);
        details.put("context", context);
        details.put("timestamp", event.getTimestamp() != null ? event.getTimestamp().toString() : null);
        details.put("userAgent", event.getUserAgent());
        
        String resourceFromMeta = getResourceFromMetadata(event);
        if (resourceFromMeta != null) {
            details.put("targetResource", resourceFromMeta);
        }

        if (event.getMetadata() != null) {
            details.put("metadata", event.getMetadata());
        }

        return toJsonString(details);
    }

    private String createThreatAssessmentParams(ThreatAssessment assessment, String evaluator,
                                              String strategy, long processingTimeMs) {
        return String.format("evaluator=%s,strategy=%s,riskScore=%.2f,confidence=%.2f,processingTime=%dms",
            evaluator, strategy, assessment.getRiskScore(), assessment.getConfidence(), processingTimeMs);
    }

    private String createThreatAssessmentDetails(ThreatAssessment assessment, String evaluator,
                                               String strategy, long processingTimeMs) {
        Map<String, Object> details = new HashMap<>();
        details.put("auditType", "THREAT_ASSESSMENT");
        details.put("assessmentId", assessment.getAssessmentId());
        details.put("evaluator", evaluator);
        details.put("strategy", strategy);
        
        details.put("action", assessment.getAction() != null ? assessment.getAction() : "ESCALATE");
        details.put("riskScore", assessment.getRiskScore());
        details.put("confidence", assessment.getConfidence());
        details.put("processingTimeMs", processingTimeMs);
        details.put("assessedAt", assessment.getAssessedAt().toString());
        details.put("recommendedActions", assessment.getRecommendedActions());

        return toJsonString(details);
    }

    private String createProcessingDecisionParams(ProcessingMode mode, String router) {
        return String.format("mode=%s,router=%s,blocking=%s,escalation=%s,monitoring=%s",
            mode.toString(), router, mode.isBlocking(), mode.needsEscalation(), mode.needsMonitoring());
    }

    private String createProcessingDecisionDetails(ProcessingMode mode, String router, String reason,
                                                 Map<String, Object> decisionContext) {
        Map<String, Object> details = new HashMap<>();
        details.put("auditType", "PROCESSING_DECISION");
        details.put("processingMode", mode.toString());
        details.put("router", router);
        details.put("reason", reason);
        details.put("isRealtime", mode.isRealtime());
        details.put("isBlocking", mode.isBlocking());
        details.put("needsEscalation", mode.needsEscalation());
        details.put("needsMonitoring", mode.needsMonitoring());
        details.put("needsHumanIntervention", mode.needsHumanIntervention());

        if (decisionContext != null) {
            details.put("decisionContext", decisionContext);
        }

        return toJsonString(details);
    }

    private String createAgentStateParams(String agentId, String previousState, String newState) {
        return String.format("agentId=%s,previousState=%s,newState=%s", agentId, previousState, newState);
    }

    private String createAgentStateDetails(String agentId, String previousState, String newState,
                                         String reason, Map<String, Object> stateContext) {
        Map<String, Object> details = new HashMap<>();
        details.put("auditType", "AGENT_STATE_CHANGE");
        details.put("agentId", agentId);
        details.put("previousState", previousState);
        details.put("newState", newState);
        details.put("reason", reason);
        details.put("timestamp", LocalDateTime.now().toString());

        if (stateContext != null) {
            details.put("stateContext", stateContext);
        }

        return toJsonString(details);
    }

    private String createPerformanceMetricsDetails(String component, Map<String, Object> metrics,
                                                 long measurementPeriodMs) {
        Map<String, Object> details = new HashMap<>();
        details.put("auditType", "PERFORMANCE_METRICS");
        details.put("component", component);
        details.put("measurementPeriodMs", measurementPeriodMs);
        details.put("timestamp", LocalDateTime.now().toString());
        details.put("metrics", metrics);

        return toJsonString(details);
    }

    private String createErrorDetails(String component, String operation, Exception exception,
                                    Map<String, Object> errorContext) {
        Map<String, Object> details = new HashMap<>();
        details.put("auditType", "ERROR");
        details.put("component", component);
        details.put("operation", operation);
        details.put("errorClass", exception.getClass().getName());
        details.put("errorMessage", exception.getMessage());
        details.put("timestamp", LocalDateTime.now().toString());

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
}