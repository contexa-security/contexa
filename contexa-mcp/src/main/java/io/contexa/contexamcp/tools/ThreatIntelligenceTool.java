package io.contexa.contexamcp.tools;

import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexamcp.adapter.ThreatIntelligenceAdapter;
import io.contexa.contexamcp.utils.SecurityToolUtils;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
@SoarTool(
        name = "threat_intelligence",
        description = "Query threat intelligence for IoCs and threat actors",
        approval = SoarTool.ApprovalRequirement.AUTO,
        auditRequired = true,
        retryable = true,
        maxRetries = 3,
        timeoutMs = 30000,
        requiredPermissions = {"threat.query", "intelligence.access"},
        allowedEnvironments = {"development", "staging", "production"}
)
public class ThreatIntelligenceTool {

    private final ThreatIntelligenceAdapter threatIntelAdapter;

    @Tool(
            name = "threat_intelligence",
            description = """
            Threat intelligence tool. Queries Indicators of Compromise (IoC) such as IP, domain, file hash, etc.
            Collects threat information. Provides known threat actors, attack campaigns, malware info,
            and generates real-time threat assessments and response recommendations.
            """
    )
    public Response queryThreatIntelligence(
            @ToolParam(description = "Indicator to query (IP address, domain, file hash, email, URL, etc.)", required = true)
            String indicator,

            @ToolParam(description = "Indicator type (ip, domain, hash, email, url). Auto-detected if not specified", required = false)
            String indicatorType) {

        long startTime = System.currentTimeMillis();

        try {
            validateRequest(indicator);

            String detectedType = detectOrValidateType(indicator, indicatorType);

            boolean externalUsed = threatIntelAdapter.isAvailable();
            ThreatIntelligence intelligence = lookupThreatIntelligence(indicator, detectedType);

            ThreatAssessment assessment = assessThreat(intelligence);
            List<String> recommendations = generateRecommendations(assessment);

            SecurityToolUtils.auditLog(
                    "threat_intelligence",
                    "query",
                    "SOAR-System",
                    String.format("Indicator=%s, Type=%s, ThreatLevel=%s, Provider=%s",
                            indicator, detectedType,
                            assessment != null ? assessment.threatLevel : "UNKNOWN",
                            threatIntelAdapter.getProviderName()),
                    "SUCCESS"
            );

            SecurityToolUtils.recordMetric("threat_intelligence", "execution_count", 1);
            SecurityToolUtils.recordMetric("threat_intelligence", "queries_processed", 1);
            if (intelligence != null) {
                SecurityToolUtils.recordMetric("threat_intelligence", "threats_found", 1);
            }
            SecurityToolUtils.recordMetric("threat_intelligence", "execution_time_ms",
                    System.currentTimeMillis() - startTime);

            return Response.builder()
                    .success(true)
                    .message(intelligence != null ?
                            "Threat intelligence found for indicator" :
                            "No threat intelligence found")
                    .indicator(indicator)
                    .indicatorType(detectedType)
                    .intelligence(intelligence)
                    .assessment(assessment)
                    .recommendations(recommendations)
                    .queryTime(LocalDateTime.now().toString())
                    .externalProviderUsed(externalUsed)
                    .providerName(threatIntelAdapter.getProviderName())
                    .build();

        } catch (Exception e) {
            log.error("Threat intelligence query failed", e);

            SecurityToolUtils.recordMetric("threat_intelligence", "error_count", 1);

            return Response.builder()
                    .success(false)
                    .message("Failed to query threat intelligence: " + e.getMessage())
                    .indicator(indicator)
                    .error(e.getMessage())
                    .build();
        }
    }

    private void validateRequest(String indicator) {
        if (indicator == null || indicator.trim().isEmpty()) {
            throw new IllegalArgumentException("Indicator is required");
        }
    }

    private String detectOrValidateType(String indicator, String indicatorType) {
        if (indicatorType != null && !indicatorType.trim().isEmpty()) {
            Set<String> validTypes = Set.of("ip", "domain", "hash", "email", "url");
            if (validTypes.contains(indicatorType.toLowerCase())) {
                return indicatorType.toLowerCase();
            }
            log.error("Invalid indicator type '{}' - falling back to auto-detection", indicatorType);
        }
        return detectIndicatorType(indicator);
    }

    private String detectIndicatorType(String indicator) {
        if (indicator.matches("^([0-9]{1,3}\\.){3}[0-9]{1,3}$")) {
            return "ip";
        } else if (indicator.matches("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\\.[a-zA-Z]{2,}$")) {
            return "domain";
        } else if (indicator.matches("^[a-fA-F0-9]{32,64}$")) {
            return "hash";
        } else if (indicator.contains("@")) {
            return "email";
        } else if (indicator.startsWith("http://") || indicator.startsWith("https://")) {
            return "url";
        }
        return "unknown";
    }

    private ThreatIntelligence lookupThreatIntelligence(String indicator, String type) {
        ThreatIntelligenceAdapter.QueryResult result =
                threatIntelAdapter.queryIndicator(indicator, type);

        if (!result.found()) {
            return null;
        }

        return ThreatIntelligence.builder()
                .indicator(indicator)
                .type(type)
                .reputation(result.reputation())
                .confidenceScore(result.confidenceScore())
                .malwareFamily(result.malwareFamily())
                .attackCampaign(result.attackCampaign())
                .tags(result.tags())
                .context(result.context())
                .source(result.source())
                .build();
    }

    private ThreatAssessment assessThreat(ThreatIntelligence intelligence) {
        if (intelligence == null) {
            return ThreatAssessment.builder()
                    .threatLevel("NONE")
                    .riskScore(0)
                    .verdict("SAFE")
                    .build();
        }

        int riskScore = calculateRiskScore(intelligence);

        String threatLevel;
        String verdict;

        if (riskScore >= 80) {
            threatLevel = "CRITICAL";
            verdict = "MALICIOUS";
        } else if (riskScore >= 60) {
            threatLevel = "HIGH";
            verdict = "SUSPICIOUS";
        } else if (riskScore >= 40) {
            threatLevel = "MEDIUM";
            verdict = "POTENTIALLY_HARMFUL";
        } else if (riskScore >= 20) {
            threatLevel = "LOW";
            verdict = "UNKNOWN";
        } else {
            threatLevel = "NONE";
            verdict = "SAFE";
        }

        return ThreatAssessment.builder()
                .threatLevel(threatLevel)
                .riskScore(riskScore)
                .verdict(verdict)
                .factors(Arrays.asList(
                        "Reputation: " + intelligence.reputation,
                        "Confidence: " + intelligence.confidenceScore
                ))
                .build();
    }

    private int calculateRiskScore(ThreatIntelligence intelligence) {
        int score = 0;

        if ("malicious".equals(intelligence.reputation)) {
            score += 50;
        } else if ("suspicious".equals(intelligence.reputation)) {
            score += 30;
        }

        score += (int) (intelligence.confidenceScore * 20);

        return Math.min(score, 100);
    }

    private List<String> generateRecommendations(ThreatAssessment assessment) {
        List<String> recommendations = new ArrayList<>();

        if (assessment == null || "NONE".equals(assessment.threatLevel)) {
            recommendations.add("No immediate action required");
            recommendations.add("Continue monitoring");
            return recommendations;
        }

        switch (assessment.threatLevel) {
            case "CRITICAL":
                recommendations.add("IMMEDIATE: Block indicator at all security layers");
                recommendations.add("Initiate incident response procedures");
                recommendations.add("Search for indicator across all systems");
                recommendations.add("Notify security team immediately");
                break;
            case "HIGH":
                recommendations.add("Block indicator at perimeter");
                recommendations.add("Investigate any connections to this indicator");
                recommendations.add("Update security signatures");
                break;
            case "MEDIUM":
                recommendations.add("Monitor for suspicious activity");
                recommendations.add("Consider blocking if additional context confirms threat");
                recommendations.add("Review logs for historical activity");
                break;
            case "LOW":
                recommendations.add("Add to watchlist");
                recommendations.add("Monitor for changes in threat status");
                break;
            default:
                break;
        }

        recommendations.add("Document findings in incident tracking system");
        return recommendations;
    }

    @Data
    @Builder
    // Threat intelligence queries external providers via adapter
    public static class Response {
        private boolean success;
        private String message;
        private String indicator;
        private String indicatorType;
        private ThreatIntelligence intelligence;
        private ThreatAssessment assessment;
        private List<String> recommendations;
        private String queryTime;
        private String error;
        private boolean externalProviderUsed;
        private String providerName;
    }

    @Data
    @Builder
    public static class ThreatIntelligence {
        private String indicator;
        private String type;
        private String reputation;
        private double confidenceScore;
        private String malwareFamily;
        private String attackCampaign;
        private List<String> tags;
        private Map<String, Object> context;
        private String source;
    }

    @Data
    @Builder
    public static class ThreatAssessment {
        private String threatLevel;
        private int riskScore;
        private String verdict;
        private List<String> factors;
    }
}
