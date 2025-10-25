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

/**
 * 정적 권한 분석 이벤트
 * 
 * AccessGovernanceLab이 권한 감사를 수행하고 문제점을 발견한 경우 발생하는 이벤트
 * 이 이벤트는 AutonomousPolicySynthesizer에 의해 수신되어
 * StaticAccessOptimizationLab으로 라우팅되어 최적화 정책 생성으로 이어짐
 * 
 * @author contexa
 * @since 1.0.0
 */
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
    
    // 권한 분석 관련 추가 정보
    private final AnalysisType analysisType;
    private final List<AccessFinding> findings;
    private final String analyzedResource;
    private final String analyzedUser;
    private final Integer totalPermissions;
    private final Integer unusedPermissions;
    private final Integer overPrivilegedCount;
    private final Map<String, Object> recommendations;
    
    /**
     * 분석 유형
     */
    public enum AnalysisType {
        UNUSED_PERMISSIONS,      // 미사용 권한
        OVER_PRIVILEGED,        // 과도한 권한
        SEPARATION_OF_DUTIES,   // 직무 분리 위반
        LEAST_PRIVILEGE,        // 최소 권한 원칙 위반
        ACCESS_REVIEW,          // 접근 권한 검토
        COMPLIANCE_CHECK        // 규정 준수 확인
    }
    
    /**
     * 권한 분석 발견 사항
     */
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
        
        // Getter 메서드 (Lombok이 자동 생성하지만 명시적으로 추가)
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
        this.responseSuccessful = true;  // 분석은 항상 성공
        this.responseDescription = "권한 분석 완료";
        
        // 컨텍스트 구성
        this.context = buildContext(additionalContext);
    }
    
    /**
     * 이벤트 컨텍스트 구성
     */
    private Map<String, Object> buildContext(Map<String, Object> additionalContext) {
        Map<String, Object> ctx = new HashMap<>();
        
        // 분석 정보
        ctx.put("analysisType", analysisType);
        ctx.put("analyzedResource", analyzedResource);
        ctx.put("analyzedUser", analyzedUser);
        
        // 통계 정보
        ctx.put("totalPermissions", totalPermissions);
        ctx.put("unusedPermissions", unusedPermissions);
        ctx.put("overPrivilegedCount", overPrivilegedCount);
        
        // 발견 사항 요약
        if (findings != null && !findings.isEmpty()) {
            ctx.put("findingsCount", findings.size());
            ctx.put("criticalFindings", countCriticalFindings());
            ctx.put("highRiskFindings", countHighRiskFindings());
        }
        
        // 권장 사항
        ctx.put("recommendations", recommendations);
        
        // 추가 컨텍스트
        if (additionalContext != null) {
            ctx.putAll(additionalContext);
        }
        
        return ctx;
    }
    
    /**
     * 정책 생성을 위한 자연어 설명 생성
     */
    public String generateNaturalLanguageDescription() {
        StringBuilder sb = new StringBuilder();
        sb.append("분석 유형: ").append(getAnalysisTypeDescription()).append("\n");
        sb.append("대상 리소스: ").append(analyzedResource != null ? analyzedResource : "전체 시스템").append("\n");
        sb.append("대상 사용자: ").append(analyzedUser != null ? analyzedUser : "전체 사용자").append("\n");
        sb.append("발견 사항: ").append(findings != null ? findings.size() : 0).append("건\n");
        
        if (unusedPermissions != null && unusedPermissions > 0) {
            sb.append("미사용 권한: ").append(unusedPermissions).append("개\n");
        }
        
        if (overPrivilegedCount != null && overPrivilegedCount > 0) {
            sb.append("과도한 권한: ").append(overPrivilegedCount).append("개\n");
        }
        
        if (!recommendations.isEmpty()) {
            sb.append("권장 사항: ").append(recommendations.size()).append("건");
        }
        
        return sb.toString();
    }
    
    /**
     * 학습을 위한 핵심 정보 추출
     */
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
                return "미사용 권한 분석";
            case OVER_PRIVILEGED:
                return "과도한 권한 분석";
            case SEPARATION_OF_DUTIES:
                return "직무 분리 검증";
            case LEAST_PRIVILEGE:
                return "최소 권한 원칙 검증";
            case ACCESS_REVIEW:
                return "접근 권한 검토";
            case COMPLIANCE_CHECK:
                return "규정 준수 확인";
            default:
                return "일반 권한 분석";
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