package io.contexa.contexacore.autonomous.event;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.context.ApplicationEvent;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@EqualsAndHashCode(callSuper = false)
public class StaticAccessAnalysisEvent extends ApplicationEvent implements LearnableEvent {
    
    private final String eventId;
    private final EventType eventType = EventType.STATIC_ACCESS_ANALYSIS;
    private final LocalDateTime occurredAt;
    private final String source;
    private final String severity;
    private final String description;
    private final Map<String, Object> context;
    private final boolean responseSuccessful;
    private final String responseDescription;

    private final AnalysisType analysisType;
    private final List<AccessFinding> findings;
    private final String analyzedResource;
    private final String analyzedUser;
    private final Integer totalPermissions;
    private final Integer unusedPermissions;
    private final Integer overPrivilegedCount;
    private final Map<String, Object> recommendations;

    public enum AnalysisType {
        UNUSED_PERMISSIONS,      
        OVER_PRIVILEGED,        
        SEPARATION_OF_DUTIES,   
        LEAST_PRIVILEGE,        
        ACCESS_REVIEW,          
        COMPLIANCE_CHECK        
    }

    @Data
    @Builder
    public static class AccessFinding {
        private String findingId;
        private String type;
        private String severity;
        private String description;
        private String affectedUser;
        private String affectedRole;
        private String affectedPermission;
        private String affectedResource;
        private String recommendation;
        private LocalDateTime lastUsed;
        private Integer riskScore;

        public String getFindingType() {
            return type;
        }
        
        public String getAffectedResource() {
            return affectedResource;
        }
    }
    
    @Builder
    public StaticAccessAnalysisEvent(
            Object eventSource,
            String severity,
            String description,
            AnalysisType analysisType,
            List<AccessFinding> findings,
            String analyzedResource,
            String analyzedUser,
            Integer totalPermissions,
            Integer unusedPermissions,
            Integer overPrivilegedCount,
            Map<String, Object> recommendations,
            Map<String, Object> additionalContext) {
        
        super(eventSource);
        this.eventId = "SAA-" + UUID.randomUUID().toString();
        this.occurredAt = LocalDateTime.now();
        this.source = eventSource != null ? eventSource.getClass().getSimpleName() : "AccessGovernanceLab";
        this.severity = severity != null ? severity : "MEDIUM";
        this.description = description;
        this.analysisType = analysisType;
        this.findings = findings;
        this.analyzedResource = analyzedResource;
        this.analyzedUser = analyzedUser;
        this.totalPermissions = totalPermissions;
        this.unusedPermissions = unusedPermissions;
        this.overPrivilegedCount = overPrivilegedCount;
        this.recommendations = recommendations != null ? recommendations : new HashMap<>();
        this.responseSuccessful = true;  
        this.responseDescription = "Permission analysis complete";

        this.context = buildContext(additionalContext);
    }

    private Map<String, Object> buildContext(Map<String, Object> additionalContext) {
        Map<String, Object> ctx = new HashMap<>();

        ctx.put("analysisType", analysisType);
        ctx.put("analyzedResource", analyzedResource);
        ctx.put("analyzedUser", analyzedUser);

        ctx.put("totalPermissions", totalPermissions);
        ctx.put("unusedPermissions", unusedPermissions);
        ctx.put("overPrivilegedCount", overPrivilegedCount);

        if (findings != null && !findings.isEmpty()) {
            ctx.put("findingsCount", findings.size());
            ctx.put("criticalFindings", countCriticalFindings());
            ctx.put("highRiskFindings", countHighRiskFindings());
        }

        ctx.put("recommendations", recommendations);

        if (additionalContext != null) {
            ctx.putAll(additionalContext);
        }
        
        return ctx;
    }

    public String generateNaturalLanguageDescription() {
        StringBuilder sb = new StringBuilder();
        sb.append("Analysis Type: ").append(getAnalysisTypeDescription()).append("\n");
        sb.append("Target Resource: ").append(analyzedResource != null ? analyzedResource : "Entire System").append("\n");
        sb.append("Target User: ").append(analyzedUser != null ? analyzedUser : "All Users").append("\n");
        sb.append("Findings: ").append(findings != null ? findings.size() : 0).append(" item(s)\n");

        if (unusedPermissions != null && unusedPermissions > 0) {
            sb.append("Unused Permissions: ").append(unusedPermissions).append("\n");
        }

        if (overPrivilegedCount != null && overPrivilegedCount > 0) {
            sb.append("Over-Privileged: ").append(overPrivilegedCount).append("\n");
        }

        if (!recommendations.isEmpty()) {
            sb.append("Recommendations: ").append(recommendations.size()).append(" item(s)");
        }
        
        return sb.toString();
    }

    public Map<String, String> extractLearningFeatures() {
        Map<String, String> features = new HashMap<>();
        features.put("analysis_type", analysisType.toString());
        features.put("severity", severity);
        features.put("findings_count", String.valueOf(findings != null ? findings.size() : 0));
        features.put("unused_ratio", calculateUnusedRatio());
        features.put("risk_level", calculateRiskLevel());
        features.put("resource_type", extractResourceType(analyzedResource));
        features.put("user_type", extractUserType(analyzedUser));
        return features;
    }
    
    private String getAnalysisTypeDescription() {
        switch (analysisType) {
            case UNUSED_PERMISSIONS:
                return "Unused Permissions Analysis";
            case OVER_PRIVILEGED:
                return "Over-Privileged Analysis";
            case SEPARATION_OF_DUTIES:
                return "Separation of Duties Verification";
            case LEAST_PRIVILEGE:
                return "Least Privilege Principle Verification";
            case ACCESS_REVIEW:
                return "Access Review";
            case COMPLIANCE_CHECK:
                return "Compliance Check";
            default:
                return "General Permission Analysis";
        }
    }
    
    private long countCriticalFindings() {
        if (findings == null) return 0;
        return findings.stream()
                .filter(f -> "CRITICAL".equals(f.getSeverity()))
                .count();
    }
    
    private long countHighRiskFindings() {
        if (findings == null) return 0;
        return findings.stream()
                .filter(f -> f.getRiskScore() != null && f.getRiskScore() >= 70)
                .count();
    }
    
    private String calculateUnusedRatio() {
        if (totalPermissions == null || totalPermissions == 0) return "0%";
        if (unusedPermissions == null) return "0%";
        double ratio = (double) unusedPermissions / totalPermissions * 100;
        return String.format("%.1f%%", ratio);
    }
    
    private String calculateRiskLevel() {
        long critical = countCriticalFindings();
        long highRisk = countHighRiskFindings();
        
        if (critical > 0) return "CRITICAL";
        if (highRisk > 2) return "HIGH";
        if (highRisk > 0) return "MEDIUM";
        return "LOW";
    }
    
    private String extractResourceType(String resource) {
        if (resource == null) return "SYSTEM";
        if (resource.contains("api")) return "API";
        if (resource.contains("database")) return "DATABASE";
        if (resource.contains("admin")) return "ADMIN";
        return "RESOURCE";
    }
    
    private String extractUserType(String user) {
        if (user == null) return "ALL";
        if (user.contains("admin")) return "ADMIN";
        if (user.contains("service")) return "SERVICE";
        if (user.contains("system")) return "SYSTEM";
        return "USER";
    }
}