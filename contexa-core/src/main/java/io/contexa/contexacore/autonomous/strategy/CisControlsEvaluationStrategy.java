package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.domain.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * CIS Controls 기반 위협 평가 전략
 * 
 * CIS Critical Security Controls (Version 8)의 18개 컨트롤을 기반으로
 * 보안 이벤트를 평가하고 우선순위가 지정된 대응 방안을 제시합니다.
 */
public class CisControlsEvaluationStrategy implements ThreatEvaluationStrategy {
    
    private static final Logger logger = LoggerFactory.getLogger(CisControlsEvaluationStrategy.class);
    
    // CIS Controls v8 - 18 Controls with Implementation Groups (IG)
    private enum CisControl {
        CONTROL_1("1", "Inventory and Control of Enterprise Assets", 1, 0.9),
        CONTROL_2("2", "Inventory and Control of Software Assets", 1, 0.9),
        CONTROL_3("3", "Data Protection", 1, 1.0),
        CONTROL_4("4", "Secure Configuration of Enterprise Assets and Software", 1, 0.8),
        CONTROL_5("5", "Account Management", 1, 0.9),
        CONTROL_6("6", "Access Control Management", 1, 1.0),
        CONTROL_7("7", "Continuous Vulnerability Management", 2, 0.8),
        CONTROL_8("8", "Audit Log Management", 2, 0.7),
        CONTROL_9("9", "Email and Web Browser Protections", 2, 0.6),
        CONTROL_10("10", "Malware Defenses", 1, 0.9),
        CONTROL_11("11", "Data Recovery", 2, 0.7),
        CONTROL_12("12", "Network Infrastructure Management", 2, 0.8),
        CONTROL_13("13", "Network Monitoring and Defense", 2, 0.8),
        CONTROL_14("14", "Security Awareness and Skills Training", 1, 0.5),
        CONTROL_15("15", "Service Provider Management", 2, 0.6),
        CONTROL_16("16", "Application Software Security", 2, 0.7),
        CONTROL_17("17", "Incident Response Management", 2, 0.9),
        CONTROL_18("18", "Penetration Testing", 3, 0.6);
        
        private final String number;
        private final String name;
        private final int implementationGroup;
        private final double importance;
        
        CisControl(String number, String name, int implementationGroup, double importance) {
            this.number = number;
            this.name = name;
            this.implementationGroup = implementationGroup;
            this.importance = importance;
        }
        
        public boolean isBasicControl() {
            return implementationGroup == 1;
        }
        
        public boolean isFoundationalControl() {
            return implementationGroup <= 2;
        }
    }
    
    // Event type to CIS Controls mapping
    private static final Map<SecurityEvent.EventType, List<CisControl>> EVENT_TO_CONTROLS = Map.ofEntries(
        Map.entry(SecurityEvent.EventType.AUTH_FAILURE, 
            List.of(CisControl.CONTROL_5, CisControl.CONTROL_6, CisControl.CONTROL_8)),
        Map.entry(SecurityEvent.EventType.PRIVILEGE_ESCALATION, 
            List.of(CisControl.CONTROL_5, CisControl.CONTROL_6, CisControl.CONTROL_4)),
        Map.entry(SecurityEvent.EventType.DATA_EXFILTRATION, 
            List.of(CisControl.CONTROL_3, CisControl.CONTROL_13, CisControl.CONTROL_17)),
        Map.entry(SecurityEvent.EventType.MALWARE_DETECTED, 
            List.of(CisControl.CONTROL_10, CisControl.CONTROL_7, CisControl.CONTROL_17)),
        Map.entry(SecurityEvent.EventType.INTRUSION_ATTEMPT, 
            List.of(CisControl.CONTROL_13, CisControl.CONTROL_12, CisControl.CONTROL_6)),
        Map.entry(SecurityEvent.EventType.POLICY_VIOLATION, 
            List.of(CisControl.CONTROL_4, CisControl.CONTROL_14, CisControl.CONTROL_8)),
        Map.entry(SecurityEvent.EventType.ANOMALY_DETECTED, 
            List.of(CisControl.CONTROL_13, CisControl.CONTROL_8, CisControl.CONTROL_17)),
        Map.entry(SecurityEvent.EventType.NETWORK_SCAN, 
            List.of(CisControl.CONTROL_13, CisControl.CONTROL_12)),
        Map.entry(SecurityEvent.EventType.SYSTEM_COMPROMISE, 
            List.of(CisControl.CONTROL_17, CisControl.CONTROL_11, CisControl.CONTROL_10))
    );
    
    // Safeguards with priorities
    private static class Safeguard {
        final String id;
        final String description;
        final int priority; // 1=highest, 3=lowest
        final CisControl control;
        
        Safeguard(String id, String description, int priority, CisControl control) {
            this.id = id;
            this.description = description;
            this.priority = priority;
            this.control = control;
        }
    }
    
    // Key safeguards for each control
    private static final Map<CisControl, List<Safeguard>> CONTROL_SAFEGUARDS = createSafeguards();
    
    private static Map<CisControl, List<Safeguard>> createSafeguards() {
        Map<CisControl, List<Safeguard>> safeguards = new HashMap<>();
        
        // Control 1: Asset Management
        safeguards.put(CisControl.CONTROL_1, List.of(
            new Safeguard("1.1", "Establish and maintain detailed enterprise asset inventory", 1, CisControl.CONTROL_1),
            new Safeguard("1.2", "Address unauthorized assets", 1, CisControl.CONTROL_1)
        ));
        
        // Control 3: Data Protection
        safeguards.put(CisControl.CONTROL_3, List.of(
            new Safeguard("3.1", "Establish and maintain data management process", 1, CisControl.CONTROL_3),
            new Safeguard("3.2", "Establish and maintain data inventory", 1, CisControl.CONTROL_3),
            new Safeguard("3.3", "Configure data access control lists", 1, CisControl.CONTROL_3),
            new Safeguard("3.8", "Document data flows", 2, CisControl.CONTROL_3),
            new Safeguard("3.11", "Encrypt sensitive data at rest", 1, CisControl.CONTROL_3),
            new Safeguard("3.12", "Encrypt sensitive data in transit", 1, CisControl.CONTROL_3)
        ));
        
        // Control 5: Account Management
        safeguards.put(CisControl.CONTROL_5, List.of(
            new Safeguard("5.1", "Establish and maintain inventory of accounts", 1, CisControl.CONTROL_5),
            new Safeguard("5.2", "Use unique passwords", 1, CisControl.CONTROL_5),
            new Safeguard("5.3", "Disable dormant accounts", 1, CisControl.CONTROL_5),
            new Safeguard("5.4", "Restrict administrator privileges", 1, CisControl.CONTROL_5)
        ));
        
        // Control 6: Access Control
        safeguards.put(CisControl.CONTROL_6, List.of(
            new Safeguard("6.1", "Establish access granting process", 1, CisControl.CONTROL_6),
            new Safeguard("6.2", "Establish access revoking process", 1, CisControl.CONTROL_6),
            new Safeguard("6.3", "Require MFA for externally exposed applications", 1, CisControl.CONTROL_6),
            new Safeguard("6.4", "Require MFA for remote access", 1, CisControl.CONTROL_6),
            new Safeguard("6.5", "Require MFA for administrative access", 1, CisControl.CONTROL_6)
        ));
        
        // Control 10: Malware Defenses
        safeguards.put(CisControl.CONTROL_10, List.of(
            new Safeguard("10.1", "Deploy and maintain anti-malware software", 1, CisControl.CONTROL_10),
            new Safeguard("10.2", "Configure automatic anti-malware signature updates", 1, CisControl.CONTROL_10),
            new Safeguard("10.3", "Disable auto-run and auto-play", 1, CisControl.CONTROL_10),
            new Safeguard("10.7", "Use behavior-based anti-malware", 2, CisControl.CONTROL_10)
        ));
        
        // Control 13: Network Monitoring
        safeguards.put(CisControl.CONTROL_13, List.of(
            new Safeguard("13.1", "Centralize security event alerting", 2, CisControl.CONTROL_13),
            new Safeguard("13.2", "Deploy security information event management (SIEM)", 2, CisControl.CONTROL_13),
            new Safeguard("13.3", "Deploy network intrusion detection", 2, CisControl.CONTROL_13),
            new Safeguard("13.6", "Collect network traffic flow logs", 2, CisControl.CONTROL_13)
        ));
        
        // Control 17: Incident Response
        safeguards.put(CisControl.CONTROL_17, List.of(
            new Safeguard("17.1", "Establish incident response program", 2, CisControl.CONTROL_17),
            new Safeguard("17.2", "Establish incident response contacts", 1, CisControl.CONTROL_17),
            new Safeguard("17.3", "Establish incident response processes", 2, CisControl.CONTROL_17),
            new Safeguard("17.4", "Establish incident response training", 2, CisControl.CONTROL_17)
        ));
        
        return safeguards;
    }
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        logger.debug("Evaluating event {} using CIS Controls framework", event.getEventId());
        
        // Extract indicators based on CIS Controls
        List<ThreatIndicator> indicators = extractIndicators(event);
        
        // Convert indicators to string list
        List<String> indicatorStrings = indicators.stream()
            .map(ind -> ind.getType() + ":" + ind.getValue())
            .toList();
        
        // Calculate risk score
        double riskScore = calculateRiskScore(indicators);
        
        // Get prioritized actions based on CIS Controls
        List<String> actions = getRecommendedActions(event);
        
        // Calculate confidence
        double confidence = calculateConfidenceScore(event);
        
        // Add CIS-specific metadata
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("cis.affected_controls", identifyAffectedControls(event));
        metadata.put("cis.implementation_group", determineImplementationGroup(event));
        metadata.put("cis.safeguards", identifySafeguards(event));
        metadata.put("cis.maturity_level", assessMaturityLevel(event));
        metadata.put("cis.priority_actions", getPriorityActions(event));
        
        // Map to CIS framework
        Map<String, String> frameworkMapping = mapToFramework(event);
        
        return ThreatAssessment.builder()
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName())
            .eventId(event.getEventId())
            .indicators(indicatorStrings)
            .riskScore(riskScore)
            .threatLevel(determineThreatLevel(riskScore))
            .recommendedActions(actions)
            .confidence(confidence)
            .metadata(metadata)
            .build();
    }
    
    @Override
    public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        if (event == null) {
            logger.warn("SecurityEvent가 null입니다. 지표 추출을 건너뜁니다.");
            return new ArrayList<>();
        }
        
        List<ThreatIndicator> indicators = new ArrayList<>();
        
        try {
            // Extract control-based indicators
            List<CisControl> affectedControls = identifyAffectedControls(event);
            for (CisControl control : affectedControls) {
                indicators.add(createControlIndicator(control, event));
            }
            
            // Extract safeguard indicators
            List<Safeguard> safeguards = identifySafeguards(event);
            for (Safeguard safeguard : safeguards) {
                indicators.add(createSafeguardIndicator(safeguard, event));
            }
            
            // Add implementation group indicator
            int ig = determineImplementationGroup(event);
            indicators.add(createImplementationGroupIndicator(ig, event));
            
            // Add maturity indicator
            String maturityLevel = assessMaturityLevel(event);
            indicators.add(createMaturityIndicator(maturityLevel, event));
            
        } catch (Exception e) {
            logger.error("CIS Controls 지표 추출 중 오류 발생", e);
        }
        
        return indicators;
    }
    
    @Override
    public String getStrategyName() {
        return "CIS Controls Evaluation Strategy";
    }
    
    @Override
    public String getDescription() {
        return "Evaluates threats based on CIS Critical Security Controls v8 (18 prioritized controls)";
    }
    
    @Override
    public Map<String, String> mapToFramework(SecurityEvent event) {
        Map<String, String> mapping = new HashMap<>();
        
        // Map to CIS Controls
        List<CisControl> controls = identifyAffectedControls(event);
        mapping.put("cis.controls", 
            controls.stream()
                .map(c -> c.number + ":" + c.name)
                .collect(Collectors.joining(", ")));
        
        // Map Implementation Group
        int ig = determineImplementationGroup(event);
        mapping.put("cis.implementation_group", "IG" + ig);
        
        // Map safeguards
        List<Safeguard> safeguards = identifySafeguards(event);
        if (!safeguards.isEmpty()) {
            mapping.put("cis.safeguards", 
                safeguards.stream()
                    .map(s -> s.id)
                    .collect(Collectors.joining(", ")));
        }
        
        // Map maturity level
        mapping.put("cis.maturity", assessMaturityLevel(event));
        
        // Map control categories
        Set<String> categories = controls.stream()
            .map(c -> {
                if (c.isBasicControl()) return "Basic";
                if (c.isFoundationalControl()) return "Foundational";
                return "Organizational";
            })
            .collect(Collectors.toSet());
        mapping.put("cis.categories", String.join(",", categories));
        
        return mapping;
    }
    
    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        List<String> actions = new ArrayList<>();
        
        // Get control-specific actions
        List<CisControl> controls = identifyAffectedControls(event);
        for (CisControl control : controls) {
            actions.addAll(getControlActions(control, event));
        }
        
        // Get safeguard-specific actions
        List<Safeguard> safeguards = identifySafeguards(event);
        for (Safeguard safeguard : safeguards) {
            if (safeguard.priority == 1) { // Only high-priority safeguards
                actions.add("Implement safeguard " + safeguard.id + ": " + safeguard.description);
            }
        }
        
        // Add priority actions based on implementation group
        actions.addAll(getPriorityActions(event));
        
        // Add maturity improvement actions
        String maturityLevel = assessMaturityLevel(event);
        if (!"Optimized".equals(maturityLevel)) {
            actions.add("Improve maturity level from " + maturityLevel + " to next level");
        }
        
        // Prioritize actions
        return prioritizeActions(actions, event);
    }
    
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        if (indicators.isEmpty()) {
            return 0.0;
        }
        
        double controlScore = 0.0;
        double safeguardScore = 0.0;
        double maturityScore = 0.0;
        int controlCount = 0;
        int safeguardCount = 0;
        
        for (ThreatIndicator indicator : indicators) {
            if (indicator.getSource().startsWith("CIS-Control")) {
                controlScore += indicator.getThreatScore();
                controlCount++;
            } else if (indicator.getSource().startsWith("CIS-Safeguard")) {
                safeguardScore += indicator.getThreatScore();
                safeguardCount++;
            } else if (indicator.getSource().startsWith("CIS-Maturity")) {
                maturityScore = indicator.getThreatScore();
            }
        }
        
        // Calculate weighted score
        double avgControlScore = controlCount > 0 ? controlScore / controlCount : 0;
        double avgSafeguardScore = safeguardCount > 0 ? safeguardScore / safeguardCount : 0;
        
        // Weight: 40% control, 30% safeguard, 30% maturity
        double baseScore = (avgControlScore * 0.4) + (avgSafeguardScore * 0.3) + (maturityScore * 0.3);
        
        // Apply implementation group multiplier
        baseScore *= getImplementationGroupMultiplier(indicators);
        
        return Math.min(Math.max(baseScore, 0.0), 1.0);
    }
    
    private ThreatIndicator createControlIndicator(CisControl control, SecurityEvent event) {
        double threatScore = control.importance * mapEventSeverityToScore(event.getSeverity());
        
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.COMPLIANCE)
            .value("Control " + control.number)
            .source("CIS-Control")
            .severity(mapScoreToSeverity(threatScore))
            .confidence(0.85)
            .threatScore(threatScore)
            .cisControl(control.number)
            .description("CIS Control " + control.number + ": " + control.name + " affected")
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private ThreatIndicator createSafeguardIndicator(Safeguard safeguard, SecurityEvent event) {
        double baseScore = safeguard.priority == 1 ? 0.8 : safeguard.priority == 2 ? 0.6 : 0.4;
        double threatScore = baseScore * safeguard.control.importance;
        
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.COMPLIANCE)
            .value("Safeguard " + safeguard.id)
            .source("CIS-Safeguard")
            .severity(mapScoreToSeverity(threatScore))
            .confidence(0.8)
            .threatScore(threatScore)
            .cisControl(safeguard.control.number)
            .description("Safeguard " + safeguard.id + ": " + safeguard.description)
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private ThreatIndicator createImplementationGroupIndicator(int ig, SecurityEvent event) {
        double threatScore = ig == 1 ? 0.5 : ig == 2 ? 0.7 : 0.9;
        
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.COMPLIANCE)
            .value("IG" + ig)
            .source("CIS-ImplementationGroup")
            .severity(mapScoreToSeverity(threatScore))
            .confidence(0.9)
            .threatScore(threatScore)
            .description("Implementation Group " + ig + " requirements")
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private ThreatIndicator createMaturityIndicator(String maturityLevel, SecurityEvent event) {
        double threatScore = switch (maturityLevel) {
            case "Initial" -> 0.9;
            case "Developing" -> 0.7;
            case "Defined" -> 0.5;
            case "Managed" -> 0.3;
            case "Optimized" -> 0.1;
            default -> 0.5;
        };
        
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.COMPLIANCE)
            .value(maturityLevel)
            .source("CIS-Maturity")
            .severity(mapScoreToSeverity(threatScore))
            .confidence(0.75)
            .threatScore(threatScore)
            .description("CIS Controls maturity level: " + maturityLevel)
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private List<CisControl> identifyAffectedControls(SecurityEvent event) {
        List<CisControl> controls = EVENT_TO_CONTROLS.getOrDefault(
            event.getEventType(), 
            List.of(CisControl.CONTROL_17) // Default to incident response
        );
        
        // Add additional controls based on event characteristics
        if (event.getSeverity() == SecurityEvent.Severity.CRITICAL) {
            if (!controls.contains(CisControl.CONTROL_17)) {
                controls = new ArrayList<>(controls);
                controls.add(CisControl.CONTROL_17); // Always include incident response for critical
            }
        }
        
        return controls;
    }
    
    private int determineImplementationGroup(SecurityEvent event) {
        // Determine based on organization size and complexity from metadata
        String orgSize = (String) event.getMetadata().getOrDefault("org_size", "medium");
        
        return switch (orgSize) {
            case "small" -> 1;  // IG1: Small organizations
            case "medium" -> 2; // IG2: Medium organizations
            case "large" -> 3;  // IG3: Large/complex organizations
            default -> 2;
        };
    }
    
    private List<Safeguard> identifySafeguards(SecurityEvent event) {
        List<Safeguard> safeguards = new ArrayList<>();
        
        List<CisControl> controls = identifyAffectedControls(event);
        for (CisControl control : controls) {
            List<Safeguard> controlSafeguards = CONTROL_SAFEGUARDS.get(control);
            if (controlSafeguards != null) {
                // Add relevant safeguards based on event type
                safeguards.addAll(controlSafeguards.stream()
                    .filter(s -> isRelevantSafeguard(s, event))
                    .collect(Collectors.toList()));
            }
        }
        
        return safeguards;
    }
    
    private boolean isRelevantSafeguard(Safeguard safeguard, SecurityEvent event) {
        // Check if safeguard is relevant for the event
        if (event.getEventType() == SecurityEvent.EventType.AUTH_FAILURE) {
            return safeguard.id.startsWith("5.") || safeguard.id.startsWith("6.");
        }
        if (event.getEventType() == SecurityEvent.EventType.MALWARE_DETECTED) {
            return safeguard.id.startsWith("10.");
        }
        if (event.getEventType() == SecurityEvent.EventType.DATA_EXFILTRATION) {
            return safeguard.id.startsWith("3.") || safeguard.id.startsWith("13.");
        }
        
        // Default: include priority 1 safeguards
        return safeguard.priority == 1;
    }
    
    private String assessMaturityLevel(SecurityEvent event) {
        // Assess based on response capabilities and controls implementation
        Map<String, Object> metadata = event.getMetadata();
        
        boolean hasAutomation = metadata.containsKey("automated_response");
        boolean hasMonitoring = metadata.containsKey("continuous_monitoring");
        boolean hasProcesses = metadata.containsKey("documented_processes");
        boolean hasMetrics = metadata.containsKey("metrics_tracking");
        boolean hasOptimization = metadata.containsKey("continuous_improvement");
        
        if (hasOptimization && hasMetrics && hasAutomation) {
            return "Optimized";
        } else if (hasMetrics && hasMonitoring) {
            return "Managed";
        } else if (hasProcesses) {
            return "Defined";
        } else if (hasMonitoring) {
            return "Developing";
        } else {
            return "Initial";
        }
    }
    
    private List<String> getControlActions(CisControl control, SecurityEvent event) {
        return switch (control) {
            case CONTROL_1 -> List.of(
                "Update asset inventory",
                "Remove unauthorized assets"
            );
            case CONTROL_3 -> List.of(
                "Review data classification",
                "Implement data encryption",
                "Update data access controls"
            );
            case CONTROL_5 -> List.of(
                "Review account privileges",
                "Disable unused accounts",
                "Enforce password policies"
            );
            case CONTROL_6 -> List.of(
                "Implement MFA",
                "Review access control lists",
                "Update access policies"
            );
            case CONTROL_10 -> List.of(
                "Update anti-malware signatures",
                "Scan all systems",
                "Enable behavior-based detection"
            );
            case CONTROL_13 -> List.of(
                "Review network monitoring coverage",
                "Update detection rules",
                "Enhance log collection"
            );
            case CONTROL_17 -> List.of(
                "Execute incident response plan",
                "Document incident details",
                "Perform root cause analysis"
            );
            default -> List.of("Review control " + control.number + " implementation");
        };
    }
    
    private List<String> getPriorityActions(SecurityEvent event) {
        List<String> actions = new ArrayList<>();
        
        int ig = determineImplementationGroup(event);
        
        // Add IG-specific priority actions
        if (ig >= 1) {
            actions.add("Implement IG1 basic cyber hygiene controls");
        }
        if (ig >= 2) {
            actions.add("Deploy SIEM and enhance monitoring (IG2)");
        }
        if (ig >= 3) {
            actions.add("Implement advanced threat detection and response (IG3)");
        }
        
        // Add event-specific priority actions
        if (event.getSeverity() == SecurityEvent.Severity.CRITICAL) {
            actions.add(0, "IMMEDIATE: Activate incident response team");
            actions.add(1, "IMMEDIATE: Contain affected systems");
        }
        
        return actions;
    }
    
    private List<String> prioritizeActions(List<String> actions, SecurityEvent event) {
        // Sort by priority keywords and control importance
        return actions.stream()
            .sorted((a, b) -> {
                // Immediate actions first
                if (a.startsWith("IMMEDIATE")) return -1;
                if (b.startsWith("IMMEDIATE")) return 1;
                
                // IG1 actions before higher IGs
                if (a.contains("IG1")) return -1;
                if (b.contains("IG1")) return 1;
                
                // Implement actions before review actions
                if (a.startsWith("Implement") && !b.startsWith("Implement")) return -1;
                if (b.startsWith("Implement") && !a.startsWith("Implement")) return 1;
                
                return 0;
            })
            .collect(Collectors.toList());
    }
    
    private double getImplementationGroupMultiplier(List<ThreatIndicator> indicators) {
        // Higher IG = better security = lower risk
        for (ThreatIndicator indicator : indicators) {
            if (indicator.getSource().equals("CIS-ImplementationGroup")) {
                String value = indicator.getValue();
                if ("IG3".equals(value)) return 0.7; // 30% risk reduction
                if ("IG2".equals(value)) return 0.85; // 15% risk reduction
                if ("IG1".equals(value)) return 1.0; // No reduction
            }
        }
        return 1.0;
    }
    
    private ThreatAssessment.ThreatLevel determineThreatLevel(double riskScore) {
        if (riskScore >= 0.8) return ThreatAssessment.ThreatLevel.CRITICAL;
        if (riskScore >= 0.6) return ThreatAssessment.ThreatLevel.HIGH;
        if (riskScore >= 0.4) return ThreatAssessment.ThreatLevel.MEDIUM;
        if (riskScore >= 0.2) return ThreatAssessment.ThreatLevel.LOW;
        return ThreatAssessment.ThreatLevel.INFO;
    }
    
    private ThreatIndicator.Severity mapScoreToSeverity(double score) {
        if (score >= 0.8) return ThreatIndicator.Severity.CRITICAL;
        if (score >= 0.6) return ThreatIndicator.Severity.HIGH;
        if (score >= 0.4) return ThreatIndicator.Severity.MEDIUM;
        if (score >= 0.2) return ThreatIndicator.Severity.LOW;
        return ThreatIndicator.Severity.INFO;
    }
    
    private double mapEventSeverityToScore(SecurityEvent.Severity severity) {
        return switch (severity) {
            case CRITICAL -> 1.0;
            case HIGH -> 0.8;
            case MEDIUM -> 0.6;
            case LOW -> 0.4;
            case INFO -> 0.2;
        };
    }
    
    /**
     * Zero Trust 아키텍처 - SecurityContext 기반 위협 평가 (기본 구현)
     */
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        return evaluate(event);
    }
}
