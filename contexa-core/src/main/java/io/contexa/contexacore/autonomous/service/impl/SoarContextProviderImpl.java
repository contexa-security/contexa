package io.contexa.contexacore.autonomous.service.impl;

import io.contexa.contexacore.autonomous.service.ISoarContextProvider;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarExecutionMode;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

public class SoarContextProviderImpl implements ISoarContextProvider {

    private static final Logger logger = LoggerFactory.getLogger(SoarContextProviderImpl.class);

    @Autowired
    private SecurityIncidentRepository securityIncidentRepository;

    @Value("${security.plane.agent.organization-id:default-org}")
    private String defaultOrganizationId;

    @Value("${security.plane.agent.execution-mode:ASYNC}")
    private String defaultExecutionMode;

    @Value("${security.plane.agent.auto-approve-low-risk:false}")
    private boolean autoApproveLowRisk;

    @Override
    public SoarContext createContextFromEvents(List<SecurityEvent> events) {
        if (events == null || events.isEmpty()) {
            logger.warn("No events provided to create SOAR context");
            return createDefaultContext();
        }

        SecurityEvent primaryEvent = events.get(0);

        String incidentId = "INC-EVT-" + primaryEvent.getEventId();

        String severity = determineSeverity(events);

        String description = String.format("Security events detected: %d events starting with %s severity",
                events.size(), primaryEvent.getSeverity());

        List<String> affectedSystems = extractAffectedSystems(events);

        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("event_count", events.size());
        additionalInfo.put("first_event_time", primaryEvent.getTimestamp());
        additionalInfo.put("event_types", extractEventTypes(events));
        additionalInfo.put("source_ips", extractSourceIps(events));

        String threatType = primaryEvent.getSeverity() != null ? primaryEvent.getSeverity().toString() : "UNKNOWN";

        SoarContext context = new SoarContext(
                incidentId,                    
                threatType,                    
                description,                   
                affectedSystems,              
                "ACTIVE",                     
                "SecurityPlaneAgent",         
                severity,                     
                String.join(", ", affectedSystems), 
                defaultOrganizationId         
        );

        context.setExecutionMode(SoarExecutionMode.valueOf(defaultExecutionMode));

        if (autoApproveLowRisk && "LOW".equals(severity)) {
            
        }

        logger.info("Created SOAR context from {} events: incidentId={}, severity={}, mode={}",
                events.size(), incidentId, severity, context.getExecutionMode());

        return context;
    }

    @Override
    @Transactional(readOnly = true)
    public SoarContext createContextFromIncident(SecurityIncident incident) {
        if (incident == null) {
            logger.warn("No incident provided to create SOAR context");
            return createDefaultContext();
        }

        SecurityIncident fullIncident = securityIncidentRepository
                .findWithTagsByIncidentId(incident.getIncidentId())
                .orElse(incident); 

        incident = fullIncident;

        String severity = mapIncidentSeverity(incident.getThreatLevel());

        List<String> affectedSystems = new ArrayList<>();
        if (incident.getAffectedSystem() != null) {
            affectedSystems.add(incident.getAffectedSystem());
        }

        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("incident_type", incident.getType().toString());
        additionalInfo.put("source", incident.getSource());
        additionalInfo.put("detection_time", incident.getDetectedAt());
        additionalInfo.put("status", incident.getStatus());

        try {
            if (incident.getTags() != null && !incident.getTags().isEmpty()) {
                
                Set<String> tags = new HashSet<>(incident.getTags());
                additionalInfo.put("tags", tags);
            }
        } catch (org.hibernate.LazyInitializationException e) {
            logger.warn("Failed to load tags for incident {}: {}", incident.getIncidentId(), e.getMessage());
            additionalInfo.put("tags", new HashSet<>());
        }

        if (incident.getRelatedEventIds() != null && !incident.getRelatedEventIds().isEmpty()) {
            additionalInfo.put("related_events", incident.getRelatedEventIds());
        }

        SoarContext context = new SoarContext(
                incident.getIncidentId(),
                "ACTIVE",
                severity,
                incident.getDescription(),
                incident.getStatus().toString(),
                incident.getDetectedAt(),
                affectedSystems,
                additionalInfo,
                defaultOrganizationId
        );

        context.setExecutionMode(SoarExecutionMode.ASYNC);

        if ("CRITICAL".equals(severity)) {
            context.setHumanApprovalNeeded(true);
            context.setHumanApprovalMessage("Critical incident requires human approval before tool execution");
        }

        logger.info("Created SOAR context from incident: {}, severity={}, approval_needed={}",
                incident.getIncidentId(), severity, context.isHumanApprovalNeeded());

        return context;
    }

    @Override
    public SoarContext enrichContext(SoarContext context, Map<String, Object> additionalInfo) {
        if (context == null) {
            logger.warn("Cannot enrich null context");
            return context;
        }

        if (additionalInfo == null || additionalInfo.isEmpty()) {
            return context;
        }

        Map<String, Object> currentInfo = context.getAdditionalInfo();
        if (currentInfo == null) {
            currentInfo = new HashMap<>();
        }
        currentInfo.putAll(additionalInfo);

        if (additionalInfo.containsKey("severity")) {
            String newSeverity = additionalInfo.get("severity").toString();
            context.setSeverity(newSeverity);
            logger.debug("Updated context severity to: {}", newSeverity);
        }

        if (additionalInfo.containsKey("executionMode")) {
            String mode = additionalInfo.get("executionMode").toString();
            context.setExecutionMode(SoarExecutionMode.valueOf(mode));
            logger.debug("Updated context execution mode to: {}", mode);
        }

        if (additionalInfo.containsKey("affectedSystems")) {
            @SuppressWarnings("unchecked")
            List<String> systems = (List<String>) additionalInfo.get("affectedSystems");
            List<String> currentSystems = context.getAffectedAssets();
            if (currentSystems == null) {
                currentSystems = new ArrayList<>();
            }
            currentSystems.addAll(systems);
            context.setAffectedAssets(currentSystems);
        }

        if (additionalInfo.containsKey("recommendedAction")) {
            String action = additionalInfo.get("recommendedAction").toString();
            if (isHighRiskAction(action)) {
                context.setHumanApprovalNeeded(true);
                context.setHumanApprovalMessage("High-risk action recommended: " + action);
            }
        }

        logger.debug("Enriched SOAR context with {} additional fields", additionalInfo.size());

        return context;
    }

    public SoarContext createDefaultContext() {
        
        String incidentId = "INC-AGENT-" + UUID.randomUUID().toString().substring(0, 8);

        SoarContext context = new SoarContext(
                incidentId,                                    
                "UNKNOWN",                                      
                "Default agent context for autonomous monitoring", 
                List.of("agent-system"),                       
                "MONITORING",                                   
                "SecurityPlaneAgent",                          
                "LOW",                                          
                "Monitor and observe",                         
                defaultOrganizationId                          
        );

        context.setExecutionMode(SoarExecutionMode.ASYNC);

        logger.debug("Created default SOAR context: {}", incidentId);

        return context;
    }

    private String determineSeverity(List<SecurityEvent> events) {
        
        Set<String> severities = events.stream()
                .map(e -> {
                    String severity = e.getSeverity().toString();
                    return severity != null ? severity : "LOW";
                })
                .collect(Collectors.toSet());

        if (severities.contains("CRITICAL")) return "CRITICAL";
        if (severities.contains("HIGH")) return "HIGH";
        if (severities.contains("MEDIUM")) return "MEDIUM";
        return "LOW";
    }

    private List<String> extractAffectedSystems(List<SecurityEvent> events) {
        return events.stream()
                .map(e -> e.getSource() != null ? e.getSource().toString() : null)
                .filter(Objects::nonNull)
                .distinct()
                .collect(Collectors.toList());
    }

    private List<String> extractEventTypes(List<SecurityEvent> events) {
        return events.stream()
                .map(e -> e.getSeverity() != null ? e.getSeverity().toString() : null)
                .filter(Objects::nonNull)
                .distinct()
                .collect(Collectors.toList());
    }

    private List<String> extractSourceIps(List<SecurityEvent> events) {
        return events.stream()
                .map(e -> {
                    Map<String, Object> details = e.getMetadata();
                    if (details != null && details.containsKey("source_ip")) {
                        return details.get("source_ip").toString();
                    }
                    return null;
                })
                .filter(Objects::nonNull)
                .distinct()
                .collect(Collectors.toList());
    }

    private String mapIncidentSeverity(SecurityIncident.ThreatLevel threatLevel) {
        if (threatLevel == null) {
            return "MEDIUM";
        }

        switch (threatLevel) {
            case CRITICAL:
                return "CRITICAL";
            case HIGH:
                return "HIGH";
            case MEDIUM:
                return "MEDIUM";
            case LOW:
                return "LOW";
            case INFO:
                return "LOW";
            default:
                return "MEDIUM";
        }
    }

    private boolean isHighRiskAction(String action) {
        
        Set<String> highRiskActions = Set.of(
                "block", "isolate", "quarantine", "shutdown",
                "delete", "terminate", "disable", "revoke"
        );

        String actionLower = action.toLowerCase();
        return highRiskActions.stream().anyMatch(actionLower::contains);
    }

    @Override
    public SoarContext createEmergencyContext(String incidentId, String description) {
        logger.warn("Creating emergency SOAR context for incident: {}", incidentId);

        SoarContext context = new SoarContext(
                incidentId,
                "EMERGENCY",
                "CRITICAL",
                description,
                "ACTIVE",
                LocalDateTime.now(),
                List.of("unknown"),
                Map.of("emergency", true, "auto_created", true),
                defaultOrganizationId
        );

        context.setExecutionMode(SoarExecutionMode.SYNC);
        context.setHumanApprovalNeeded(true);
        context.setHumanApprovalMessage("Emergency situation requires immediate human approval");
        context.setEmergencyMode(true);

        return context;
    }

    @Override
    public SoarContext createContextFromThreatIndicators(List<ThreatIndicator> threatIndicators) {
        if (threatIndicators == null || threatIndicators.isEmpty()) {
            logger.warn("No threat indicators provided to create SOAR context");
            return createDefaultContext();
        }

        ThreatIndicator primaryIndicator = threatIndicators.get(0);
        String incidentId = "INC-TI-" + primaryIndicator.getIndicatorId();

        SoarContext context = new SoarContext(
                incidentId,
                "THREAT_INDICATORS",
                primaryIndicator.getSeverity().toString(),
                "Threat indicators analysis: " + threatIndicators.size() + " indicators detected",
                "ACTIVE",
                LocalDateTime.now(),
                List.of("network", "endpoints"),
                Map.of("indicator_count", threatIndicators.size(), "primary_type", primaryIndicator.getType()),
                defaultOrganizationId
        );

        context.setExecutionMode(SoarExecutionMode.ASYNC);
        
        context.setHumanApprovalNeeded(threatIndicators.stream()
            .anyMatch(indicator -> indicator.getSeverity() == ThreatIndicator.Severity.CRITICAL &&
                                   indicator.getConfidence() > 0.8));

        logger.info("Created SOAR context from {} threat indicators: {}", threatIndicators.size(), incidentId);

        return context;
    }
}