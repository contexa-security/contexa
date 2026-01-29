package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.event.ProcessingCompletedEvent;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.orchestrator.strategy.ProcessingStrategy;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@RequiredArgsConstructor
public class ProcessingExecutionHandler implements SecurityEventHandler {

    private final List<ProcessingStrategy> strategies;
    private final ApplicationEventPublisher eventPublisher;

    @Autowired(required = false)
    private SecurityIncidentRepository incidentRepository;

    @Value("${security.plane.agent.name:SecurityPlaneAgent-1}")
    private String agentName;

    private final Map<ProcessingMode, ProcessingStrategy> strategyCache = new ConcurrentHashMap<>();

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        ProcessingMode mode = (ProcessingMode) context.getMetadata().get("processingMode");

        if (mode == null) {
            context.markAsFailed("No processing mode determined");
            return false;
        }

        try {

            ProcessingStrategy strategy = selectStrategy(mode);

            if (strategy == null) {
                return handleNoStrategyAvailable(context, mode);
            }

            long startTime = System.currentTimeMillis();
            ProcessingResult result = strategy.process(context);
            long executionTime = System.currentTimeMillis() - startTime;

            handleProcessingResult(context, result, executionTime);

            if (result.isRequiresIncident()) {
                createIncidentFromResult(event, result, context);
            }

            publishProcessingCompletedEvent(event, result, mode, executionTime);

            return result.isSuccess();

        } catch (Exception e) {
            log.error("[ProcessingExecutionHandler] Error executing processing for event: {}", event.getEventId(), e);
            context.markAsFailed("Processing execution error: " + e.getMessage());
            return false;
        }
    }

    private ProcessingStrategy selectStrategy(ProcessingMode mode) {
        ProcessingStrategy cached = strategyCache.get(mode);
        if (cached != null) {
            return cached;
        }

        for (ProcessingStrategy strategy : strategies) {
            if (strategy.supports(mode)) {
                strategyCache.put(mode, strategy);
                return strategy;
            }
        }

        return null;
    }

    private boolean handleNoStrategyAvailable(SecurityEventContext context, ProcessingMode mode) {
        log.warn("[ProcessingExecutionHandler] No strategy available for mode: {}, using fallback", mode);

        ProcessingResult fallbackResult = ProcessingResult.builder()
                .success(true)
                .processingPath(ProcessingResult.ProcessingPath.BYPASS)
                .message("No specific strategy, event logged")
                .build();

        context.addMetadata("processingResult", fallbackResult);
        context.addMetadata("fallbackUsed", true);
        context.addResponseAction("FALLBACK", "Event logged without specific processing");

        if (mode.needsEscalation()) {
            context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.AWAITING_APPROVAL);
        }

        return true;
    }

    private void handleProcessingResult(SecurityEventContext context, ProcessingResult result, long executionTime) {

        context.addMetadata("processingResult", result);
        context.addMetadata("processingSuccess", result.isSuccess());
        context.addMetadata("processingPath", result.getProcessingPath());
        context.addMetadata("processingExecutionTime", executionTime);

        double riskScore = result.getRiskScore();
        context.addMetadata("riskScore", riskScore);

        if (result.getExecutedActions() != null && !result.getExecutedActions().isEmpty()) {
            for (String action : result.getExecutedActions()) {
                context.addResponseAction(action, "Executed by " + result.getProcessingPath());
            }
        }

        if (result.getMetadata() != null) {
            result.getMetadata().forEach(context::addMetadata);
        }

        if (result.getIncidentSeverity() != null) {
            context.addMetadata("incidentCreated", true);
            context.addMetadata("incidentSeverity", result.getIncidentSeverity());
        }

        if (result.isSuccess()) {
            if (context.getProcessingStatus() != SecurityEventContext.ProcessingStatus.AWAITING_APPROVAL) {
                context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.RESPONDING);
            }
        } else {
            context.markAsFailed(result.getMessage());
        }

        SecurityEventContext.ProcessingMetrics metrics = context.getProcessingMetrics();
        if (metrics == null) {
            metrics = new SecurityEventContext.ProcessingMetrics();
            context.setProcessingMetrics(metrics);
        }
        metrics.setResponseTimeMs(executionTime);
    }

    private void createIncidentFromResult(SecurityEvent event, ProcessingResult result,
                                          SecurityEventContext context) {
        if (incidentRepository == null) {
            log.warn("[ProcessingExecutionHandler] SecurityIncidentRepository not available, cannot create incident");
            return;
        }

        try {

            String severityStr = result.getIncidentSeverity();
            ProcessingResult.IncidentSeverity severity = severityStr != null ?
                    ProcessingResult.IncidentSeverity.valueOf(severityStr) :
                    ProcessingResult.IncidentSeverity.MEDIUM;
            SecurityIncident.ThreatLevel threatLevel = mapSeverityToThreatLevel(severity);

            SecurityIncident incident = SecurityIncident.builder()
                    .incidentId("INC-" + result.getProcessingPath() + "-" + System.currentTimeMillis())

                    .type(determineIncidentType(result))
                    .threatLevel(threatLevel)
                    .status(SecurityIncident.IncidentStatus.NEW)
                    .description(String.format("%s path detected %s threat",
                            result.getProcessingPath(), severity))
                    .sourceIp(event.getSourceIp())
                    .affectedUser(event.getUserId())
                    .detectedBy(agentName)
                    .detectionSource(result.getProcessingPath() != null ?
                            result.getProcessingPath().toString() : "PIPELINE")
                    .detectedAt(LocalDateTime.now())
                    .riskScore(result.getCurrentRiskLevel())
                    .autoResponseEnabled(severity == ProcessingResult.IncidentSeverity.CRITICAL)
                    .build();

            SecurityIncident saved = incidentRepository.save(incident);

            context.addMetadata("incidentId", saved.getIncidentId());
            context.addMetadata("incidentCreated", true);
            context.addMetadata("incidentSeverity", severity.toString());

            log.warn("[ProcessingExecutionHandler] Incident created: {} for event: {} - severity: {}",
                    saved.getIncidentId(), event.getEventId(), severity);

        } catch (Exception e) {
            log.error("[ProcessingExecutionHandler] Failed to create incident for event: {}",
                    event.getEventId(), e);
        }
    }

    private SecurityIncident.ThreatLevel mapSeverityToThreatLevel(ProcessingResult.IncidentSeverity severity) {
        switch (severity) {
            case CRITICAL:
                return SecurityIncident.ThreatLevel.CRITICAL;
            case HIGH:
                return SecurityIncident.ThreatLevel.HIGH;
            case MEDIUM:
                return SecurityIncident.ThreatLevel.MEDIUM;
            case LOW:
                return SecurityIncident.ThreatLevel.LOW;
            default:
                return SecurityIncident.ThreatLevel.MEDIUM;
        }
    }

    private SecurityIncident.IncidentType determineIncidentType(ProcessingResult result) {
        if (result == null) {
            return SecurityIncident.IncidentType.SUSPICIOUS_ACTIVITY;
        }

        String action = null;

        if (result.getMetadata() != null) {
            Object actionObj = result.getMetadata().get("action");
            if (actionObj != null) {
                action = actionObj.toString();
            }
        }

        if (action == null && result.getAnalysisData() != null) {
            Object actionObj = result.getAnalysisData().get("action");
            if (actionObj != null) {
                action = actionObj.toString();
            }
        }

        if (action != null) {
            switch (action.toUpperCase()) {
                case "BLOCK":
                case "B":
                    return SecurityIncident.IncidentType.INTRUSION;
                case "ESCALATE":
                case "E":
                    return SecurityIncident.IncidentType.SUSPICIOUS_ACTIVITY;
                case "CHALLENGE":
                case "C":
                    return SecurityIncident.IncidentType.POLICY_VIOLATION;
                case "ALLOW":
                case "A":
                default:
                    return SecurityIncident.IncidentType.OTHER;
            }
        }

        double riskScore = result.getRiskScore();
        if (riskScore >= 0.8) {
            return SecurityIncident.IncidentType.INTRUSION;
        } else if (riskScore >= 0.6) {
            return SecurityIncident.IncidentType.SUSPICIOUS_ACTIVITY;
        }

        return SecurityIncident.IncidentType.SUSPICIOUS_ACTIVITY;
    }

    @Deprecated(since = "4.1.0", forRemoval = true)
    private SecurityIncident.IncidentType mapSeverityToIncidentType(SecurityEvent.Severity severity) {

        return SecurityIncident.IncidentType.SUSPICIOUS_ACTIVITY;
    }

    private void publishProcessingCompletedEvent(SecurityEvent event, ProcessingResult result,
                                                 ProcessingMode mode, long processingTimeMs) {
        try {

            ProcessingCompletedEvent.ProcessingLayer layer = ProcessingCompletedEvent.ProcessingLayer.UNKNOWN;

            if (result.isAiAnalysisPerformed()) {
                int aiLevel = result.getAiAnalysisLevel();
                layer = ProcessingCompletedEvent.ProcessingLayer.fromLevel(aiLevel);
            } else {

                if (mode == ProcessingMode.REALTIME_BLOCK) {
                    layer = ProcessingCompletedEvent.ProcessingLayer.LAYER1;
                }
            }

            ProcessingCompletedEvent completedEvent = new ProcessingCompletedEvent(
                    this,
                    event,
                    result,
                    mode,
                    layer,
                    processingTimeMs
            );

            eventPublisher.publishEvent(completedEvent);

        } catch (Exception e) {

            log.error("[ProcessingExecutionHandler] Failed to publish ProcessingCompletedEvent for event: {}",
                    event.getEventId(), e);
        }
    }

    @Override
    public String getName() {
        return "ProcessingExecutionHandler";
    }

    @Override
    public int getOrder() {
        return 50;
    }
}