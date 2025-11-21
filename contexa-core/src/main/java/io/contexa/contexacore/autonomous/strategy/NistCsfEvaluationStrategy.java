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
 * NIST Cybersecurity Framework 기반 위협 평가 전략
 * 
 * NIST CSF의 5가지 핵심 기능(Identify, Protect, Detect, Respond, Recover)을
 * 기반으로 보안 이벤트를 평가하고 대응 방안을 제시합니다.
 */
public class NistCsfEvaluationStrategy implements ThreatEvaluationStrategy {
    
    private static final Logger logger = LoggerFactory.getLogger(NistCsfEvaluationStrategy.class);
    
    // NIST CSF Core Functions
    private enum CoreFunction {
        IDENTIFY("ID", "Asset Management, Risk Assessment, Governance"),
        PROTECT("PR", "Access Control, Training, Data Security, Protective Technology"),
        DETECT("DE", "Anomalies, Continuous Monitoring, Detection Processes"),
        RESPOND("RS", "Response Planning, Communications, Analysis, Mitigation"),
        RECOVER("RC", "Recovery Planning, Improvements, Communications");
        
        private final String code;
        private final String description;
        
        CoreFunction(String code, String description) {
            this.code = code;
            this.description = description;
        }
    }
    
    // NIST CSF Categories with risk weights
    private static final Map<String, Double> CATEGORY_RISK_WEIGHTS = Map.ofEntries(
        // IDENTIFY
        Map.entry("ID.AM", 0.3), // Asset Management
        Map.entry("ID.BE", 0.2), // Business Environment
        Map.entry("ID.GV", 0.3), // Governance
        Map.entry("ID.RA", 0.5), // Risk Assessment
        Map.entry("ID.RM", 0.4), // Risk Management Strategy
        Map.entry("ID.SC", 0.4), // Supply Chain Risk Management
        
        // PROTECT
        Map.entry("PR.AC", 0.7), // Identity Management and Access Control
        Map.entry("PR.AT", 0.3), // Awareness and Training
        Map.entry("PR.DS", 0.8), // Data Security
        Map.entry("PR.IP", 0.5), // Information Protection Processes
        Map.entry("PR.MA", 0.4), // Maintenance
        Map.entry("PR.PT", 0.6), // Protective Technology
        
        // DETECT
        Map.entry("DE.AE", 0.7), // Anomalies and Events
        Map.entry("DE.CM", 0.6), // Security Continuous Monitoring
        Map.entry("DE.DP", 0.5), // Detection Processes
        
        // RESPOND
        Map.entry("RS.RP", 0.5), // Response Planning
        Map.entry("RS.CO", 0.4), // Communications
        Map.entry("RS.AN", 0.7), // Analysis
        Map.entry("RS.MI", 0.8), // Mitigation
        Map.entry("RS.IM", 0.6), // Improvements
        
        // RECOVER
        Map.entry("RC.RP", 0.6), // Recovery Planning
        Map.entry("RC.IM", 0.5), // Improvements
        Map.entry("RC.CO", 0.4)  // Communications
    );
    
    // Event type to NIST category mapping
    private static final Map<SecurityEvent.EventType, List<String>> EVENT_TO_CATEGORIES = Map.ofEntries(
        Map.entry(SecurityEvent.EventType.AUTH_FAILURE, List.of("PR.AC", "DE.AE")),
        Map.entry(SecurityEvent.EventType.PRIVILEGE_ESCALATION, List.of("PR.AC", "DE.AE", "RS.AN")),
        Map.entry(SecurityEvent.EventType.DATA_EXFILTRATION, List.of("PR.DS", "DE.CM", "RS.MI")),
        Map.entry(SecurityEvent.EventType.MALWARE_DETECTED, List.of("PR.PT", "DE.AE", "RS.MI")),
        Map.entry(SecurityEvent.EventType.INTRUSION_ATTEMPT, List.of("PR.PT", "DE.CM", "RS.AN")),
        Map.entry(SecurityEvent.EventType.POLICY_VIOLATION, List.of("PR.IP", "DE.DP", "RS.IM")),
        Map.entry(SecurityEvent.EventType.ANOMALY_DETECTED, List.of("DE.AE", "RS.AN")),
        Map.entry(SecurityEvent.EventType.NETWORK_SCAN, List.of("DE.CM", "RS.AN")),
        Map.entry(SecurityEvent.EventType.SYSTEM_COMPROMISE, List.of("PR.AC", "DE.AE", "RS.MI", "RC.RP"))
    );
    
    // Implementation tiers
    private enum ImplementationTier {
        PARTIAL(1, "Partial", 0.25),
        RISK_INFORMED(2, "Risk Informed", 0.50),
        REPEATABLE(3, "Repeatable", 0.75),
        ADAPTIVE(4, "Adaptive", 1.0);
        
        private final int level;
        private final String name;
        private final double maturityScore;
        
        ImplementationTier(int level, String name, double maturityScore) {
            this.level = level;
            this.name = name;
            this.maturityScore = maturityScore;
        }
    }
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        logger.debug("Evaluating event {} using NIST CSF framework", event.getEventId());
        
        // Extract indicators
        List<ThreatIndicator> indicators = extractIndicators(event);
        
        // Convert indicators to string list
        List<String> indicatorStrings = indicators.stream()
            .map(ind -> ind.getType() + ":" + ind.getValue())
            .toList();
        
        // Calculate risk score based on NIST categories
        double riskScore = calculateRiskScore(indicators);
        
        // Get recommended actions based on NIST response guidelines
        List<String> actions = getRecommendedActions(event);
        
        // Calculate confidence
        double confidence = calculateConfidenceScore(event);
        
        // Add NIST-specific metadata
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("nist.functions", identifyAffectedFunctions(event));
        metadata.put("nist.categories", identifyAffectedCategories(event));
        metadata.put("nist.implementation_tier", assessImplementationTier(event));
        metadata.put("nist.maturity_score", calculateMaturityScore(event));
        metadata.put("nist.compliance_gaps", identifyComplianceGaps(event));
        
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
            // Extract NIST category-based indicators
            List<String> categories = EVENT_TO_CATEGORIES.getOrDefault(
                event.getEventType(), List.of());
        
            for (String category : categories) {
                indicators.add(createCategoryIndicator(category, event));
            }
            
            // Extract function-based indicators
            Set<CoreFunction> affectedFunctions = identifyAffectedFunctions(event);
            for (CoreFunction function : affectedFunctions) {
                indicators.add(createFunctionIndicator(function, event));
            }
            
            // Extract compliance-based indicators
            List<String> gaps = identifyComplianceGaps(event);
            for (String gap : gaps) {
                indicators.add(createComplianceGapIndicator(gap, event));
            }
            
            // Add event-specific indicators
            if (event.getSeverity() == SecurityEvent.Severity.CRITICAL) {
                indicators.add(createCriticalEventIndicator(event));
            }
            
        } catch (Exception e) {
            logger.error("NIST CSF 지표 추출 중 오류 발생", e);
        }
        
        return indicators;
    }
    
    @Override
    public String getStrategyName() {
        return "NIST CSF Evaluation Strategy";
    }
    
    @Override
    public String getDescription() {
        return "Evaluates threats based on NIST Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover)";
    }
    
    @Override
    public Map<String, String> mapToFramework(SecurityEvent event) {
        Map<String, String> mapping = new HashMap<>();
        
        // Map to NIST CSF functions
        Set<CoreFunction> functions = identifyAffectedFunctions(event);
        mapping.put("nist.functions", 
            functions.stream()
                .map(f -> f.code)
                .collect(Collectors.joining(",")));
        
        // Map to NIST CSF categories
        List<String> categories = identifyAffectedCategories(event);
        mapping.put("nist.categories", String.join(",", categories));
        
        // Map subcategories based on event details
        List<String> subcategories = mapToSubcategories(event);
        if (!subcategories.isEmpty()) {
            mapping.put("nist.subcategories", String.join(",", subcategories));
        }
        
        // Add implementation tier
        ImplementationTier tier = assessImplementationTier(event);
        mapping.put("nist.implementation_tier", tier.name);
        mapping.put("nist.tier_level", String.valueOf(tier.level));
        
        // Add profile information
        String profile = determineProfile(event);
        mapping.put("nist.profile", profile);
        
        return mapping;
    }
    
    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        List<String> actions = new ArrayList<>();
        
        // Get function-specific recommendations
        Set<CoreFunction> functions = identifyAffectedFunctions(event);
        
        for (CoreFunction function : functions) {
            actions.addAll(getFunctionRecommendations(function, event));
        }
        
        // Add category-specific actions
        List<String> categories = identifyAffectedCategories(event);
        for (String category : categories) {
            actions.addAll(getCategoryActions(category, event));
        }
        
        // Add tier improvement recommendations
        ImplementationTier currentTier = assessImplementationTier(event);
        if (currentTier.level < 4) {
            actions.add("Improve to " + getNextTier(currentTier).name + " tier: " + 
                getTierImprovementActions(currentTier));
        }
        
        // Add compliance gap remediation
        List<String> gaps = identifyComplianceGaps(event);
        if (!gaps.isEmpty()) {
            actions.add("Address compliance gaps: " + String.join(", ", gaps));
        }
        
        // Prioritize actions based on risk
        return prioritizeActions(actions, event);
    }
    
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        if (indicators.isEmpty()) {
            return 0.0;
        }
        
        double categoryScore = 0.0;
        double functionScore = 0.0;
        double gapScore = 0.0;
        int categoryCount = 0;
        int functionCount = 0;
        int gapCount = 0;
        
        for (ThreatIndicator indicator : indicators) {
            String source = indicator.getSource();
            
            if (source.startsWith("NIST-Category")) {
                categoryScore += indicator.getThreatScore();
                categoryCount++;
            } else if (source.startsWith("NIST-Function")) {
                functionScore += indicator.getThreatScore();
                functionCount++;
            } else if (source.startsWith("NIST-Gap")) {
                gapScore += indicator.getThreatScore();
                gapCount++;
            }
        }
        
        // Calculate weighted average
        double avgCategoryScore = categoryCount > 0 ? categoryScore / categoryCount : 0;
        double avgFunctionScore = functionCount > 0 ? functionScore / functionCount : 0;
        double avgGapScore = gapCount > 0 ? gapScore / gapCount : 0;
        
        // Weight: 40% category, 30% function, 30% gap
        double baseScore = (avgCategoryScore * 0.4) + (avgFunctionScore * 0.3) + (avgGapScore * 0.3);
        
        // Apply maturity multiplier
        double maturityMultiplier = calculateMaturityMultiplier(indicators);
        double finalScore = baseScore * maturityMultiplier;
        
        return Math.min(Math.max(finalScore, 0.0), 1.0);
    }
    
    private ThreatIndicator createCategoryIndicator(String category, SecurityEvent event) {
        double weight = CATEGORY_RISK_WEIGHTS.getOrDefault(category, 0.5);
        
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.COMPLIANCE)
            .value(category)
            .source("NIST-Category")
            .severity(mapSeverityFromWeight(weight))
            .confidence(0.8)
            .threatScore(weight * mapEventSeverityToScore(event.getSeverity()))
            .nistCsfCategory(category)
            .description("NIST CSF Category: " + category + " affected")
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private ThreatIndicator createFunctionIndicator(CoreFunction function, SecurityEvent event) {
        double baseScore = switch (function) {
            case IDENTIFY -> 0.4;
            case PROTECT -> 0.7;
            case DETECT -> 0.6;
            case RESPOND -> 0.8;
            case RECOVER -> 0.9;
        };
        
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.COMPLIANCE)
            .value(function.code)
            .source("NIST-Function")
            .severity(mapSeverityFromScore(baseScore))
            .confidence(0.85)
            .threatScore(baseScore)
            .nistCsfCategory(function.code)
            .description("NIST CSF Function: " + function.name() + " - " + function.description)
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private ThreatIndicator createComplianceGapIndicator(String gap, SecurityEvent event) {
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.COMPLIANCE)
            .value(gap)
            .source("NIST-Gap")
            .severity(ThreatIndicator.Severity.HIGH)
            .confidence(0.7)
            .threatScore(0.7)
            .description("Compliance gap identified: " + gap)
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private ThreatIndicator createCriticalEventIndicator(SecurityEvent event) {
        return ThreatIndicator.builder()
            .indicatorId(UUID.randomUUID().toString())
            .type(ThreatIndicator.IndicatorType.EVENT)
            .value(event.getEventType().toString())
            .source("NIST-Critical")
            .severity(ThreatIndicator.Severity.CRITICAL)
            .confidence(0.9)
            .threatScore(0.9)
            .description("Critical event requiring immediate NIST CSF response")
            .detectedAt(LocalDateTime.now())
            .status(ThreatIndicator.IndicatorStatus.ACTIVE)
            .build();
    }
    
    private Set<CoreFunction> identifyAffectedFunctions(SecurityEvent event) {
        Set<CoreFunction> functions = new HashSet<>();
        
        switch (event.getEventType()) {
            case AUTH_FAILURE:
            case PRIVILEGE_ESCALATION:
                functions.add(CoreFunction.PROTECT);
                functions.add(CoreFunction.DETECT);
                break;
            case DATA_EXFILTRATION:
                functions.add(CoreFunction.PROTECT);
                functions.add(CoreFunction.DETECT);
                functions.add(CoreFunction.RESPOND);
                break;
            case MALWARE_DETECTED:
                functions.add(CoreFunction.DETECT);
                functions.add(CoreFunction.RESPOND);
                break;
            case SYSTEM_COMPROMISE:
                functions.add(CoreFunction.DETECT);
                functions.add(CoreFunction.RESPOND);
                functions.add(CoreFunction.RECOVER);
                break;
            case INCIDENT_CREATED:
                functions.add(CoreFunction.RESPOND);
                if (event.getSeverity() == SecurityEvent.Severity.CRITICAL) {
                    functions.add(CoreFunction.RECOVER);
                }
                break;
            default:
                functions.add(CoreFunction.DETECT);
        }
        
        return functions;
    }
    
    private List<String> identifyAffectedCategories(SecurityEvent event) {
        return EVENT_TO_CATEGORIES.getOrDefault(event.getEventType(), List.of("DE.AE"));
    }
    
    private List<String> mapToSubcategories(SecurityEvent event) {
        List<String> subcategories = new ArrayList<>();
        
        // Example subcategory mappings
        if (event.getEventType() == SecurityEvent.EventType.AUTH_FAILURE) {
            subcategories.add("PR.AC-1"); // Identities and credentials managed
            subcategories.add("DE.AE-1"); // Network operations baseline established
        }
        
        if (event.getEventType() == SecurityEvent.EventType.DATA_EXFILTRATION) {
            subcategories.add("PR.DS-1"); // Data-at-rest protected
            subcategories.add("PR.DS-2"); // Data-in-transit protected
            subcategories.add("DE.CM-1"); // Network monitored
        }
        
        return subcategories;
    }
    
    private ImplementationTier assessImplementationTier(SecurityEvent event) {
        // Assess based on event handling and response capabilities
        Map<String, Object> metadata = event.getMetadata();
        
        boolean hasAutomatedResponse = metadata.containsKey("automated_response");
        boolean hasRiskAssessment = metadata.containsKey("risk_assessment");
        boolean hasAdaptiveControl = metadata.containsKey("adaptive_control");
        boolean hasProcessDocumentation = metadata.containsKey("process_documented");
        
        if (hasAdaptiveControl && hasAutomatedResponse) {
            return ImplementationTier.ADAPTIVE;
        } else if (hasProcessDocumentation && hasRiskAssessment) {
            return ImplementationTier.REPEATABLE;
        } else if (hasRiskAssessment) {
            return ImplementationTier.RISK_INFORMED;
        } else {
            return ImplementationTier.PARTIAL;
        }
    }
    
    private double calculateMaturityScore(SecurityEvent event) {
        ImplementationTier tier = assessImplementationTier(event);
        double baseScore = tier.maturityScore;
        
        // Adjust based on response effectiveness
        if (event.getMetadata().containsKey("response_time")) {
            int responseTime = Integer.parseInt(event.getMetadata().get("response_time").toString());
            if (responseTime < 5) baseScore += 0.1; // Fast response
            else if (responseTime > 60) baseScore -= 0.1; // Slow response
        }
        
        return Math.min(Math.max(baseScore, 0.0), 1.0);
    }
    
    private List<String> identifyComplianceGaps(SecurityEvent event) {
        List<String> gaps = new ArrayList<>();
        
        // Check for missing controls based on event type
        switch (event.getEventType()) {
            case AUTH_FAILURE:
                if (event.getMetadata() != null && !event.getMetadata().containsKey("mfa_enabled")) {
                    gaps.add("PR.AC-7: MFA not implemented");
                }
                break;
            case DATA_EXFILTRATION:
                gaps.add("PR.DS-1: Data-at-rest encryption missing");
                gaps.add("DE.CM-1: Network monitoring insufficient");
                break;
            case MALWARE_DETECTED:
                if (event.getMetadata() != null && !event.getMetadata().containsKey("endpoint_protection")) {
                    gaps.add("PR.PT-3: Endpoint protection not deployed");
                }
                break;
        }
        
        return gaps;
    }
    
    private String determineProfile(SecurityEvent event) {
        // Determine security profile based on industry/context
        String industry = event.getMetadata() != null ? 
            (String) event.getMetadata().getOrDefault("industry", "general") : "general";
        
        return switch (industry) {
            case "financial" -> "Financial Services Profile";
            case "healthcare" -> "Healthcare Sector Profile";
            case "energy" -> "Energy Sector Profile";
            case "government" -> "Government Profile";
            default -> "General Security Profile";
        };
    }
    
    private List<String> getFunctionRecommendations(CoreFunction function, SecurityEvent event) {
        return switch (function) {
            case IDENTIFY -> List.of(
                "Update asset inventory",
                "Reassess risk profile",
                "Review governance policies"
            );
            case PROTECT -> List.of(
                "Strengthen access controls",
                "Review data protection measures",
                "Update protective technology"
            );
            case DETECT -> List.of(
                "Enhance monitoring capabilities",
                "Review detection processes",
                "Update anomaly baselines"
            );
            case RESPOND -> List.of(
                "Execute response plan",
                "Coordinate with stakeholders",
                "Perform impact analysis"
            );
            case RECOVER -> List.of(
                "Initiate recovery procedures",
                "Document lessons learned",
                "Update recovery plans"
            );
        };
    }
    
    private List<String> getCategoryActions(String category, SecurityEvent event) {
        // Simplified category action mapping
        if (category.startsWith("PR.AC")) {
            return List.of("Review access controls", "Verify identity management");
        } else if (category.startsWith("DE.")) {
            return List.of("Enhance detection capabilities", "Review monitoring coverage");
        } else if (category.startsWith("RS.")) {
            return List.of("Execute response procedures", "Document incident");
        }
        
        return List.of("Review " + category + " controls");
    }
    
    private ImplementationTier getNextTier(ImplementationTier current) {
        return switch (current) {
            case PARTIAL -> ImplementationTier.RISK_INFORMED;
            case RISK_INFORMED -> ImplementationTier.REPEATABLE;
            case REPEATABLE -> ImplementationTier.ADAPTIVE;
            case ADAPTIVE -> ImplementationTier.ADAPTIVE;
        };
    }
    
    private String getTierImprovementActions(ImplementationTier current) {
        return switch (current) {
            case PARTIAL -> "Implement risk assessment processes";
            case RISK_INFORMED -> "Document and standardize processes";
            case REPEATABLE -> "Implement adaptive and predictive capabilities";
            case ADAPTIVE -> "Maintain current tier";
        };
    }
    
    private List<String> prioritizeActions(List<String> actions, SecurityEvent event) {
        // Sort actions by priority based on event severity
        if (event.getSeverity() == SecurityEvent.Severity.CRITICAL) {
            // Put response and recovery actions first
            return actions.stream()
                .sorted((a, b) -> {
                    if (a.contains("Execute") || a.contains("Initiate")) return -1;
                    if (b.contains("Execute") || b.contains("Initiate")) return 1;
                    return 0;
                })
                .collect(Collectors.toList());
        }
        
        return actions;
    }
    
    private ThreatAssessment.ThreatLevel determineThreatLevel(double riskScore) {
        if (riskScore >= 0.8) return ThreatAssessment.ThreatLevel.CRITICAL;
        if (riskScore >= 0.6) return ThreatAssessment.ThreatLevel.HIGH;
        if (riskScore >= 0.4) return ThreatAssessment.ThreatLevel.MEDIUM;
        if (riskScore >= 0.2) return ThreatAssessment.ThreatLevel.LOW;
        return ThreatAssessment.ThreatLevel.INFO;
    }
    
    private ThreatIndicator.Severity mapSeverityFromWeight(double weight) {
        if (weight >= 0.8) return ThreatIndicator.Severity.CRITICAL;
        if (weight >= 0.6) return ThreatIndicator.Severity.HIGH;
        if (weight >= 0.4) return ThreatIndicator.Severity.MEDIUM;
        if (weight >= 0.2) return ThreatIndicator.Severity.LOW;
        return ThreatIndicator.Severity.INFO;
    }
    
    private ThreatIndicator.Severity mapSeverityFromScore(double score) {
        return mapSeverityFromWeight(score);
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
    
    private double calculateMaturityMultiplier(List<ThreatIndicator> indicators) {
        // Higher maturity reduces risk impact
        double avgConfidence = indicators.stream()
            .mapToDouble(ThreatIndicator::getConfidence)
            .average()
            .orElse(0.5);
        
        // Better detection confidence means better maturity
        if (avgConfidence > 0.8) return 0.8; // 20% risk reduction
        if (avgConfidence > 0.6) return 0.9; // 10% risk reduction
        return 1.0; // No reduction
    }
    
    /**
     * Zero Trust 아키텍처 - SecurityContext 기반 위협 평가 (기본 구현)
     */
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        return evaluate(event);
    }
}
