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

import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * SOAR Context Provider Íµ¨ÌòÑÏ≤?
 * 
 * Security Plane???¥Î≤§?∏Ï? ?∏Ïãú?òÌä∏Î•?SOAR ContextÎ°?Î≥Ä?òÌï©?àÎã§.
 * 24?úÍ∞Ñ ?êÏú® ?êÏù¥?ÑÌä∏ Î™®Îìú?êÏÑú??ÎπÑÎèôÍ∏??§Ìñâ Î™®ÎìúÎ•?Í∏∞Î≥∏?ºÎ°ú ?¨Ïö©?©Îãà??
 */

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
        
        // ?¥Î≤§?∏Îì§Î°úÎ???Ïª®ÌÖç?§Ìä∏ ?ùÏÑ±
        SecurityEvent primaryEvent = events.get(0);
        
        // ?∏Ïãú?òÌä∏ ID ?ùÏÑ± (?¥Î≤§??Í∏∞Î∞ò)
        String incidentId = "INC-EVT-" + primaryEvent.getEventId();
        
        // ?¨Í∞Å??Í≤∞Ï†ï (Í∞Ä???íÏ? ?¨Í∞Å???†ÌÉù)
        String severity = determineSeverity(events);
        
        // ?§Î™Ö ?ùÏÑ±
        String description = String.format("Security events detected: %d events starting with %s", 
            events.size(), primaryEvent.getEventType());
        
        // ?ÅÌñ•Î∞õÎäî ?úÏä§??Ï∂îÏ∂ú
        List<String> affectedSystems = extractAffectedSystems(events);
        
        // Ï∂îÍ? ?ïÎ≥¥ ?òÏßë
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("event_count", events.size());
        additionalInfo.put("first_event_time", primaryEvent.getTimestamp());
        additionalInfo.put("event_types", extractEventTypes(events));
        additionalInfo.put("source_ips", extractSourceIps(events));
        
        // ?ÑÌòë ?Ä??Í≤∞Ï†ï
        String threatType = primaryEvent.getEventType().toString();
        
        // SoarContext ?ùÏÑ±
        SoarContext context = new SoarContext(
            incidentId,                    // incidentId
            threatType,                    // threatType  
            description,                   // description
            affectedSystems,              // affectedAssets
            "ACTIVE",                     // currentStatus
            "SecurityPlaneAgent",         // detectedSource
            severity,                     // severity
            String.join(", ", affectedSystems), // recommendedActions
            defaultOrganizationId         // organizationId
        );
        
        // ?§Ìñâ Î™®Îìú ?§Ï†ï (Agent??Í∏∞Î≥∏?ÅÏúºÎ°?ÎπÑÎèôÍ∏?
        context.setExecutionMode(SoarExecutionMode.valueOf(defaultExecutionMode));
        
        // ?êÎèô ?πÏù∏ ?§Ï†ï
        if (autoApproveLowRisk && "LOW".equals(severity)) {
            // context.setAutoApproved(true); // Method doesn't exist
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

        // LazyInitializationException??Î∞©Ï??òÍ∏∞ ?ÑÌï¥ ?úÍ∑∏?Ä ?®Íªò ?§Ïãú Ï°∞Ìöå
        SecurityIncident fullIncident = securityIncidentRepository
                .findWithTagsByIncidentId(incident.getIncidentId())
                .orElse(incident); // Ï°∞Ìöå ?§Ìå® ???êÎ≥∏ ?¨Ïö©

        // ?¥ÌõÑ Ï≤òÎ¶¨?êÏÑú fullIncident ?¨Ïö©
        incident = fullIncident;
        
        // ?∏Ïãú?òÌä∏Î°úÎ???ÏßÅÏ†ë Ïª®ÌÖç?§Ìä∏ ?ùÏÑ±
        String severity = mapIncidentSeverity(incident.getThreatLevel());
        
        // ?ÅÌñ•Î∞õÎäî ?úÏä§??
        List<String> affectedSystems = new ArrayList<>();
        if (incident.getAffectedSystem() != null) {
            affectedSystems.add(incident.getAffectedSystem());
        }
        
        // Ï∂îÍ? ?ïÎ≥¥
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("incident_type", incident.getType().toString());
        additionalInfo.put("source", incident.getSource());
        additionalInfo.put("detection_time", incident.getDetectedAt());
        additionalInfo.put("status", incident.getStatus());
        
        // ?úÍ∑∏ Ï∂îÍ? (LazyInitializationException Î∞©Ï?)
        try {
            if (incident.getTags() != null && !incident.getTags().isEmpty()) {
                // Ïª¨Î†â?òÏùÑ ?àÎ°ú??HashSet?ºÎ°ú Î≥µÏÇ¨?òÏó¨ ÏßÄ??Î°úÎî© Î¨∏Ï†ú ?¥Í≤∞
                Set<String> tags = new HashSet<>(incident.getTags());
                additionalInfo.put("tags", tags);
            }
        } catch (org.hibernate.LazyInitializationException e) {
            logger.warn("Failed to load tags for incident {}: {}", incident.getIncidentId(), e.getMessage());
            additionalInfo.put("tags", new HashSet<>());
        }
        
        // Í¥Ä???¥Î≤§??ID??
        if (incident.getRelatedEventIds() != null && !incident.getRelatedEventIds().isEmpty()) {
            additionalInfo.put("related_events", incident.getRelatedEventIds());
        }
        
        // SoarContext ?ùÏÑ±
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
        
        // Agent Î™®Îìú?êÏÑú??ÎπÑÎèôÍ∏??§Ìñâ
        context.setExecutionMode(SoarExecutionMode.ASYNC);
        
        // Critical ?∏Ïãú?òÌä∏???¥Î®º ?πÏù∏ ?ÑÏöî
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
        
        // Í∏∞Ï°¥ Ï∂îÍ? ?ïÎ≥¥?Ä Î≥ëÌï©
        Map<String, Object> currentInfo = context.getAdditionalInfo();
        if (currentInfo == null) {
            currentInfo = new HashMap<>();
        }
        currentInfo.putAll(additionalInfo);
        
        // ?πÏ†ï ?§Ïóê ?∞Î•∏ Ïª®ÌÖç?§Ìä∏ ?ÖÎç∞?¥Ìä∏
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
        
        // Ï∂îÏ≤ú ?°ÏÖò???àÏúºÎ©??πÏù∏ ?ÑÏöî ?úÏãú
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
        // Í∏∞Î≥∏ Ïª®ÌÖç?§Ìä∏ ?ùÏÑ± (Agent ?ÑÏö©)
        String incidentId = "INC-AGENT-" + UUID.randomUUID().toString().substring(0, 8);
        
        SoarContext context = new SoarContext(
            incidentId,                                    // incidentId
            "UNKNOWN",                                      // threatType
            "Default agent context for autonomous monitoring", // description
            List.of("agent-system"),                       // affectedAssets
            "MONITORING",                                   // currentStatus
            "SecurityPlaneAgent",                          // detectedSource
            "LOW",                                          // severity
            "Monitor and observe",                         // recommendedActions
            defaultOrganizationId                          // organizationId
        );
        
        // Agent????ÉÅ ÎπÑÎèôÍ∏?Î™®Îìú
        context.setExecutionMode(SoarExecutionMode.ASYNC);
        // context.setAutoApproved(false); // Method doesn't exist
        
        logger.debug("Created default SOAR context: {}", incidentId);
        
        return context;
    }
    
    // ?¨Ìçº Î©îÏÑú?úÎì§
    
    private String determineSeverity(List<SecurityEvent> events) {
        // ?¥Î≤§?∏Îì§ Ï§?Í∞Ä???íÏ? ?¨Í∞Å??Î∞òÌôò
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
            .map(e -> e.getEventType().toString())
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
        // Í≥†ÏúÑ???°ÏÖò ?êÎ≥Ñ
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
        
        // Emergency context??Ï¶âÏãú ?§Ìñâ, ?πÏù∏ ?ÑÏöî
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
        context.setHumanApprovalNeeded(threatIndicators.stream().anyMatch(ThreatIndicator::requiresImmediateAction));
        
        logger.info("Created SOAR context from {} threat indicators: {}", threatIndicators.size(), incidentId);
        
        return context;
    }
}
