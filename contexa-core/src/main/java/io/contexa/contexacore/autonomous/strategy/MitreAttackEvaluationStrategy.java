package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment.ThreatLevel;
import io.contexa.contexacore.autonomous.domain.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * MITRE ATT&CK 프레임워크 기반 위협 평가 전략
 * 
 * MITRE ATT&CK 프레임워크의 Tactics, Techniques, Procedures (TTPs)를 기반으로
 * 보안 이벤트를 평가하고 위협 수준을 결정합니다.
 */
@Component
public class MitreAttackEvaluationStrategy implements ThreatEvaluationStrategy {
    
    private static final Logger logger = LoggerFactory.getLogger(MitreAttackEvaluationStrategy.class);
    
    // MITRE ATT&CK Tactics
    private static final Map<String, String> TACTICS = Map.ofEntries(
        Map.entry("TA0001", "Initial Access"),
        Map.entry("TA0002", "Execution"),
        Map.entry("TA0003", "Persistence"),
        Map.entry("TA0004", "Privilege Escalation"),
        Map.entry("TA0005", "Defense Evasion"),
        Map.entry("TA0006", "Credential Access"),
        Map.entry("TA0007", "Discovery"),
        Map.entry("TA0008", "Lateral Movement"),
        Map.entry("TA0009", "Collection"),
        Map.entry("TA0010", "Exfiltration"),
        Map.entry("TA0011", "Command and Control"),
        Map.entry("TA0040", "Impact")
    );
    
    // Technique to Tactic mapping (simplified subset)
    private static final Map<String, List<String>> TECHNIQUE_TO_TACTICS = Map.ofEntries(
        Map.entry("T1190", List.of("TA0001")), // Exploit Public-Facing Application
        Map.entry("T1133", List.of("TA0001", "TA0003")), // External Remote Services
        Map.entry("T1059", List.of("TA0002")), // Command and Scripting Interpreter
        Map.entry("T1053", List.of("TA0002", "TA0003", "TA0004")), // Scheduled Task/Job
        Map.entry("T1078", List.of("TA0001", "TA0003", "TA0004", "TA0005")), // Valid Accounts
        Map.entry("T1055", List.of("TA0004", "TA0005")), // Process Injection
        Map.entry("T1003", List.of("TA0006")), // OS Credential Dumping
        Map.entry("T1110", List.of("TA0006")), // Brute Force
        Map.entry("T1057", List.of("TA0007")), // Process Discovery
        Map.entry("T1021", List.of("TA0008")), // Remote Services
        Map.entry("T1005", List.of("TA0009")), // Data from Local System
        Map.entry("T1048", List.of("TA0010")), // Exfiltration Over Alternative Protocol
        Map.entry("T1071", List.of("TA0011")), // Application Layer Protocol
        Map.entry("T1486", List.of("TA0040")) // Data Encrypted for Impact
    );
    
    // High-risk techniques
    private static final Set<String> HIGH_RISK_TECHNIQUES = Set.of(
        "T1003", // OS Credential Dumping
        "T1055", // Process Injection
        "T1078", // Valid Accounts
        "T1110", // Brute Force
        "T1486", // Data Encrypted for Impact (Ransomware)
        "T1190", // Exploit Public-Facing Application
        "T1133"  // External Remote Services
    );
    
    // Attack patterns and their risk scores
    private static final Map<String, Double> ATTACK_PATTERN_SCORES = Map.ofEntries(
        Map.entry("reconnaissance", 0.3),
        Map.entry("weaponization", 0.4),
        Map.entry("delivery", 0.5),
        Map.entry("exploitation", 0.7),
        Map.entry("installation", 0.8),
        Map.entry("command_control", 0.8),
        Map.entry("actions_on_objectives", 0.9)
    );
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        logger.debug("Evaluating event {} using MITRE ATT&CK framework", event.getEventId());
        
        // Null 체크 - eventType이 없으면 기본 평가 반환
        if (event.getEventType() == null) {
            logger.warn("Event {} has null eventType, returning default assessment", event.getEventId());
            return ThreatAssessment.builder()
                .assessmentId(UUID.randomUUID().toString())
                .eventId(event.getEventId())
                .threatLevel(ThreatLevel.LOW)
                .riskScore(0.1)
                .confidence(0.3)
                .evaluator("MITRE ATT&CK")
                .description("Unable to assess - event type is null")
                .metadata(new HashMap<>())
                .recommendedActions(List.of("Review event data quality"))
                .build();
        }
        
        // Extract MITRE indicators
        List<ThreatIndicator> indicators = extractIndicators(event);
        List<String> indicatorStrings = indicators.stream()
            .map(ind -> ind.getType() + ":" + ind.getValue())
            .toList();
        
        // Calculate risk score
        double riskScore = calculateRiskScore(indicators);
        
        // Get recommended actions
        List<String> actions = getRecommendedActions(event);
        
        // Calculate confidence
        double confidence = calculateConfidenceScore(event);
        
        // Extract tactics and techniques
        List<String> tactics = extractTactics(event);
        List<String> techniques = extractTechniques(event);
        
        // Add metadata
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("mitre.tactics", tactics);
        metadata.put("mitre.techniques", techniques);
        metadata.put("mitre.attack_chain_phase", determineAttackChainPhase(event));
        metadata.put("mitre.threat_groups", identifyThreatGroups(event));
        
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
            .tactics(tactics)
            .techniques(techniques)
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
            // Extract MITRE-specific indicators
            if (event.getMitreAttackId() != null) {
                indicators.add(createMitreIndicator(event.getMitreAttackId(), event));
            }
            
            // Check for known attack patterns
            detectAttackPatterns(event).forEach(pattern -> 
                indicators.add(createPatternIndicator(pattern, event)));
            
            // Check for suspicious behaviors
            detectSuspiciousBehaviors(event).forEach(behavior ->
                indicators.add(createBehaviorIndicator(behavior, event)));
            
            // Extract network-based indicators
            if (event.getSourceIp() != null) {
                indicators.add(createNetworkIndicator(event));
            }
            
            // Extract authentication-based indicators
            if (event.getUserId() != null && isAuthenticationRelated(event)) {
                indicators.add(createAuthIndicator(event));
            }
            
        } catch (Exception e) {
            logger.error("MITRE ATT&CK 지표 추출 중 오류 발생", e);
        }
        
        return indicators;
    }
    
    @Override
    public String getStrategyName() {
        return "MITRE ATT&CK Evaluation Strategy";
    }
    
    @Override
    public String getDescription() {
        return "Evaluates threats based on MITRE ATT&CK framework TTPs (Tactics, Techniques, and Procedures)";
    }
    
    @Override
    public Map<String, String> mapToFramework(SecurityEvent event) {
        Map<String, String> mapping = new HashMap<>();
        
        // Map to MITRE ATT&CK
        if (event.getMitreAttackId() != null) {
            String techniqueId = extractTechniqueId(event.getMitreAttackId());
            mapping.put("mitre.technique", techniqueId);
            
            // Map to tactics
            List<String> tactics = TECHNIQUE_TO_TACTICS.getOrDefault(techniqueId, List.of());
            if (!tactics.isEmpty()) {
                mapping.put("mitre.tactics", String.join(",", tactics));
                mapping.put("mitre.tactics_names", 
                    tactics.stream()
                        .map(TACTICS::get)
                        .collect(Collectors.joining(",")));
            }
        }
        
        // Map event type to MITRE phases
        String attackPhase = mapEventTypeToAttackPhase(event.getEventType());
        if (attackPhase != null) {
            mapping.put("mitre.attack_phase", attackPhase);
        }
        
        // Map to kill chain
        String killChainPhase = mapToKillChain(event);
        if (killChainPhase != null) {
            mapping.put("mitre.kill_chain_phase", killChainPhase);
        }
        
        return mapping;
    }
    
    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        List<String> actions = new ArrayList<>();
        
        String techniqueId = extractTechniqueId(event.getMitreAttackId());
        
        // Technique-specific mitigations
        if (techniqueId != null) {
            actions.addAll(getMitigationsForTechnique(techniqueId));
        }
        
        // Event type-specific actions
        switch (event.getEventType()) {
            case INTRUSION_ATTEMPT:
                actions.add("Block source IP at perimeter firewall");
                actions.add("Enable enhanced monitoring for target systems");
                actions.add("Review and harden exposed services");
                break;
            case PRIVILEGE_ESCALATION:
                actions.add("Isolate affected account");
                actions.add("Reset credentials for affected and related accounts");
                actions.add("Review privilege assignment policies");
                actions.add("Enable MFA for privileged accounts");
                break;
            case DATA_EXFILTRATION:
                actions.add("Block outbound connections to suspicious destinations");
                actions.add("Enable DLP policies");
                actions.add("Review data classification and access controls");
                actions.add("Investigate scope of data exposure");
                break;
            case MALWARE_DETECTED:
                actions.add("Quarantine infected systems");
                actions.add("Update antivirus signatures");
                actions.add("Scan all systems for similar indicators");
                actions.add("Review malware behavior for lateral movement");
                break;
            case AUTH_FAILURE:
                if (event.getMetadata().getOrDefault("attempt_count", "0").equals("5")) {
                    actions.add("Lock account after repeated failures");
                    actions.add("Alert security team for potential brute force");
                }
                actions.add("Monitor for credential stuffing patterns");
                break;
            default:
                actions.add("Investigate event context and correlate with other activities");
                actions.add("Update security monitoring rules");
        }
        
        // Add general MITRE-based recommendations
        if (isHighRiskTechnique(techniqueId)) {
            actions.add(0, "CRITICAL: High-risk MITRE technique detected - immediate response required");
            actions.add("Initiate incident response procedure");
            actions.add("Preserve forensic evidence");
        }
        
        return actions;
    }
    
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        if (indicators.isEmpty()) {
            return 0.0;
        }
        
        double maxScore = 0.0;
        double avgScore = 0.0;
        double techniqueBonus = 0.0;
        
        for (ThreatIndicator indicator : indicators) {
            double score = indicator.getThreatScore();
            
            // Check for high-risk MITRE techniques
            if (indicator.getMitreAttackId() != null) {
                String techniqueId = extractTechniqueId(indicator.getMitreAttackId());
                if (HIGH_RISK_TECHNIQUES.contains(techniqueId)) {
                    techniqueBonus = Math.max(techniqueBonus, 0.3);
                    score *= 1.5; // Amplify score for high-risk techniques
                }
            }
            
            maxScore = Math.max(maxScore, score);
            avgScore += score;
        }
        
        avgScore /= indicators.size();
        
        // Weighted combination: 60% max, 30% average, 10% technique bonus
        double finalScore = (maxScore * 0.6) + (avgScore * 0.3) + techniqueBonus;
        
        // Factor in attack chain progression
        double chainMultiplier = calculateChainProgressionMultiplier(indicators);
        finalScore *= chainMultiplier;
        
        return Math.min(Math.max(finalScore, 0.0), 1.0);
    }
    
    private ThreatIndicator createMitreIndicator(String mitreId, SecurityEvent event) {
        String techniqueId = extractTechniqueId(mitreId);
        boolean isHighRisk = HIGH_RISK_TECHNIQUES.contains(techniqueId);
        
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.BEHAVIORAL)
            .value(mitreId)
            .source("MITRE ATT&CK")
            .severity(isHighRisk ? ThreatIndicator.Severity.HIGH : ThreatIndicator.Severity.MEDIUM)
            .confidence(0.8)
            .threatScore(isHighRisk ? 0.8 : 0.6)
            .mitreAttackId(mitreId)
            .description("MITRE ATT&CK Technique: " + techniqueId)
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private ThreatIndicator createPatternIndicator(String pattern, SecurityEvent event) {
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.PATTERN)
            .value(pattern)
            .source("Pattern Detection")
            .severity(ThreatIndicator.Severity.MEDIUM)
            .confidence(0.7)
            .threatScore(ATTACK_PATTERN_SCORES.getOrDefault(pattern, 0.5))
            .description("Attack pattern detected: " + pattern)
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private ThreatIndicator createBehaviorIndicator(String behavior, SecurityEvent event) {
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.BEHAVIORAL)
            .value(behavior)
            .source("Behavior Analysis")
            .severity(determineBehaviorSeverity(behavior))
            .confidence(0.6)
            .threatScore(calculateBehaviorScore(behavior))
            .description("Suspicious behavior: " + behavior)
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private ThreatIndicator createNetworkIndicator(SecurityEvent event) {
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.IP_ADDRESS)
            .value(event.getSourceIp())
            .source("Network Analysis")
            .severity(mapEventSeverity(event.getSeverity()))
            .confidence(0.7)
            .threatScore(0.5)
            .description("Network activity from: " + event.getSourceIp())
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private ThreatIndicator createAuthIndicator(SecurityEvent event) {
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.USER_ACCOUNT)
            .value(event.getUserId())
            .source("Authentication Analysis")
            .severity(ThreatIndicator.Severity.MEDIUM)
            .confidence(0.8)
            .threatScore(0.6)
            .description("Authentication anomaly for user: " + event.getUserId())
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private List<String> extractTactics(SecurityEvent event) {
        if (event.getMitreAttackId() == null) {
            return List.of();
        }
        
        String techniqueId = extractTechniqueId(event.getMitreAttackId());
        return TECHNIQUE_TO_TACTICS.getOrDefault(techniqueId, List.of());
    }
    
    private List<String> extractTechniques(SecurityEvent event) {
        List<String> techniques = new ArrayList<>();
        
        if (event.getMitreAttackId() != null) {
            techniques.add(extractTechniqueId(event.getMitreAttackId()));
        }
        
        // Infer techniques from event type
        techniques.addAll(inferTechniquesFromEventType(event.getEventType()));
        
        return techniques;
    }
    
    private String extractTechniqueId(String mitreId) {
        if (mitreId == null) return null;
        
        // Extract technique ID (e.g., T1059 from T1059.001)
        if (mitreId.startsWith("T")) {
            int dotIndex = mitreId.indexOf('.');
            return dotIndex > 0 ? mitreId.substring(0, dotIndex) : mitreId;
        }
        
        return mitreId;
    }
    
    private List<String> inferTechniquesFromEventType(SecurityEvent.EventType type) {
        return switch (type) {
            case INTRUSION_ATTEMPT -> List.of("T1190", "T1133");
            case PRIVILEGE_ESCALATION -> List.of("T1078", "T1055");
            case AUTH_FAILURE -> List.of("T1110");
            case MALWARE_DETECTED -> List.of("T1059", "T1055");
            case DATA_EXFILTRATION -> List.of("T1048");
            case COMMAND_CONTROL -> List.of("T1071");
            default -> List.of();
        };
    }
    
    private String determineAttackChainPhase(SecurityEvent event) {
        if (event.getEventType() == null) {
            return "unknown";
        }
        return switch (event.getEventType()) {
            case NETWORK_SCAN -> "reconnaissance";
            case INTRUSION_ATTEMPT -> "delivery";
            case INTRUSION_SUCCESS -> "exploitation";
            case MALWARE_DETECTED -> "installation";
            case COMMAND_CONTROL -> "command_control";
            case DATA_EXFILTRATION -> "actions_on_objectives";
            default -> "unknown";
        };
    }
    
    private List<String> identifyThreatGroups(SecurityEvent event) {
        List<String> groups = new ArrayList<>();
        
        // This would normally query a threat intelligence database
        // For now, using simplified logic based on techniques
        String techniqueId = extractTechniqueId(event.getMitreAttackId());
        if (techniqueId != null) {
            // Example mappings
            if (techniqueId.equals("T1486")) {
                groups.add("Ransomware Groups");
            }
            if (techniqueId.equals("T1003")) {
                groups.add("APT Groups");
            }
        }
        
        return groups;
    }
    
    private List<String> detectAttackPatterns(SecurityEvent event) {
        List<String> patterns = new ArrayList<>();
        
        // Detect based on event metadata and characteristics
        if (event.getEventType() != null) {
            if (event.getEventType() == SecurityEvent.EventType.NETWORK_SCAN) {
                patterns.add("reconnaissance");
            }
            
            if (event.getEventType() == SecurityEvent.EventType.AUTH_FAILURE &&
                Integer.parseInt(String.valueOf(event.getMetadata().getOrDefault("attempt_count", "0"))) > 3) {
                patterns.add("brute_force");
            }
        }
        
        return patterns;
    }
    
    private List<String> detectSuspiciousBehaviors(SecurityEvent event) {
        List<String> behaviors = new ArrayList<>();
        
        // Detect anomalous behaviors
        if (event.getMetadata().containsKey("unusual_time")) {
            behaviors.add("off_hours_activity");
        }
        
        if (event.getMetadata().containsKey("unusual_location")) {
            behaviors.add("geographic_anomaly");
        }
        
        if (event.getMetadata().containsKey("rapid_succession")) {
            behaviors.add("automated_activity");
        }
        
        return behaviors;
    }
    
    private boolean isAuthenticationRelated(SecurityEvent event) {
        if (event.getEventType() == null) {
            return event.getSource() == SecurityEvent.EventSource.IAM;
        }
        return event.getEventType() == SecurityEvent.EventType.AUTH_FAILURE ||
               event.getEventType() == SecurityEvent.EventType.PRIVILEGE_ESCALATION ||
               event.getSource() == SecurityEvent.EventSource.IAM;
    }
    
    private String mapEventTypeToAttackPhase(SecurityEvent.EventType type) {
        return switch (type) {
            case NETWORK_SCAN -> "Discovery";
            case INTRUSION_ATTEMPT -> "Initial Access";
            case PRIVILEGE_ESCALATION -> "Privilege Escalation";
            case MALWARE_DETECTED -> "Execution";
            case DATA_EXFILTRATION -> "Exfiltration";
            case COMMAND_CONTROL -> "Command and Control";
            default -> null;
        };
    }
    
    private String mapToKillChain(SecurityEvent event) {
        if (event.getEventType() == null) {
            return "Unknown";
        }
        return switch (event.getEventType()) {
            case NETWORK_SCAN -> "Reconnaissance";
            case INTRUSION_ATTEMPT -> "Weaponization";
            case INTRUSION_SUCCESS -> "Delivery";
            case MALWARE_DETECTED -> "Exploitation";
            case COMMAND_CONTROL -> "Installation";
            case DATA_EXFILTRATION -> "Actions on Objectives";
            default -> "Unknown";
        };
    }
    
    private List<String> getMitigationsForTechnique(String techniqueId) {
        // Simplified mitigation mappings
        return switch (techniqueId) {
            case "T1190" -> List.of(
                "Patch vulnerable applications",
                "Implement WAF rules",
                "Enable application sandboxing"
            );
            case "T1110" -> List.of(
                "Implement account lockout policies",
                "Enable MFA",
                "Monitor authentication logs"
            );
            case "T1003" -> List.of(
                "Enable Credential Guard",
                "Restrict LSASS access",
                "Monitor process access to LSASS"
            );
            case "T1055" -> List.of(
                "Enable process injection detection",
                "Implement application whitelisting",
                "Monitor process creation events"
            );
            case "T1486" -> List.of(
                "Implement backup strategy",
                "Enable ransomware protection",
                "Block known ransomware indicators"
            );
            default -> List.of(
                "Review MITRE mitigation for " + techniqueId,
                "Enhance monitoring for this technique"
            );
        };
    }
    
    private boolean isHighRiskTechnique(String techniqueId) {
        return techniqueId != null && HIGH_RISK_TECHNIQUES.contains(techniqueId);
    }
    
    private ThreatAssessment.ThreatLevel determineThreatLevel(double riskScore) {
        if (riskScore >= 0.9) return ThreatAssessment.ThreatLevel.CRITICAL;
        if (riskScore >= 0.7) return ThreatAssessment.ThreatLevel.HIGH;
        if (riskScore >= 0.5) return ThreatAssessment.ThreatLevel.MEDIUM;
        if (riskScore >= 0.3) return ThreatAssessment.ThreatLevel.LOW;
        return ThreatAssessment.ThreatLevel.INFO;
    }
    
    private ThreatIndicator.Severity determineBehaviorSeverity(String behavior) {
        return switch (behavior) {
            case "off_hours_activity" -> ThreatIndicator.Severity.MEDIUM;
            case "geographic_anomaly" -> ThreatIndicator.Severity.HIGH;
            case "automated_activity" -> ThreatIndicator.Severity.MEDIUM;
            default -> ThreatIndicator.Severity.LOW;
        };
    }
    
    private double calculateBehaviorScore(String behavior) {
        return switch (behavior) {
            case "off_hours_activity" -> 0.4;
            case "geographic_anomaly" -> 0.7;
            case "automated_activity" -> 0.5;
            default -> 0.3;
        };
    }
    
    private ThreatIndicator.Severity mapEventSeverity(SecurityEvent.Severity severity) {
        return switch (severity) {
            case CRITICAL -> ThreatIndicator.Severity.CRITICAL;
            case HIGH -> ThreatIndicator.Severity.HIGH;
            case MEDIUM -> ThreatIndicator.Severity.MEDIUM;
            case LOW -> ThreatIndicator.Severity.LOW;
            case INFO -> ThreatIndicator.Severity.INFO;
        };
    }
    
    private double calculateChainProgressionMultiplier(List<ThreatIndicator> indicators) {
        // Check for attack chain progression
        Set<String> phases = new HashSet<>();
        for (ThreatIndicator indicator : indicators) {
            if (indicator.getDescription() != null && indicator.getDescription().contains("Attack pattern")) {
                phases.add(indicator.getValue());
            }
        }
        
        // More phases = more advanced attack
        if (phases.size() >= 4) return 1.5;
        if (phases.size() >= 3) return 1.3;
        if (phases.size() >= 2) return 1.1;
        return 1.0;
    }
    
    /**
     * Zero Trust 아키텍처 - SecurityContext 기반 위협 평가 (기본 구현)
     */
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        return evaluate(event);
    }
}
