package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.domain.context.IAMContext;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;

/**
 * AI 보안 어드바이저 (Security Copilot)를 위한 특화된 IAM 컨텍스트
 * 
 * 포괄적 보안 분석에 필요한 모든 컨텍스트 정보를 포함
 * 다중 Lab 협업을 통한 보안 분석 지원
 * 
 * 지원하는 보안 분석 유형:
 * - 권한 감사: "과도한 권한을 가진 사용자 찾기"
 * - 위험도 평가: "현재 시스템의 보안 위험 분석"
 * - 정책 검토: "보안 정책 개선 방안 제시"
 * - 컴플라이언스 확인: "규정 준수 상태 점검"
 */
@Getter
@Setter
public class SecurityCopilotContext extends IAMContext {
    
    // 보안 질의 정보
    private String securityQuery;
    private String analysisScope; // COMPREHENSIVE, PERMISSION_AUDIT, RISK_ASSESSMENT, POLICY_REVIEW
    private String priority; // HIGH, MEDIUM, LOW
    private String queryLanguage = "ko";
    private Map<String, Object> securityMetadata;
    
    // 분석 대상 범위
    private List<String> targetUsers;
    private List<String> targetRoles;
    private List<String> targetResources;
    private List<String> targetPermissions;
    private Set<String> excludedEntities;
    
    // 보안 정책 정보
    private Map<String, Object> securityPolicies;
    private List<String> complianceRequirements;
    private Map<String, String> riskThresholds;
    
    // Lab 협업 설정
    private boolean enableStudioAnalysis = true;
    private boolean enableRiskAssessment = true;
    private boolean enablePolicyGeneration = true;
    private int maxExecutionTimeSeconds = 300;
    private String collaborationMode = "SEQUENTIAL"; // SEQUENTIAL, PARALLEL, HYBRID
    
    // 분석 설정
    private String detailLevel = "COMPREHENSIVE"; // SUMMARY, DETAILED, COMPREHENSIVE
    private boolean includeRecommendations = true;
    private boolean includeRiskScore = true;
    private boolean includeActionPlan = true;
    private int maxRecommendations = 10;
    
    // 보안 제약사항
    private boolean includeSensitiveData = false;
    private Set<String> sensitiveFields;
    private String dataClassification = "INTERNAL"; // PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    
    /**
     * 보안 분석 범위 열거형
     */
    public enum AnalysisScope {
        COMPREHENSIVE("포괄적 보안 분석"),
        PERMISSION_AUDIT("권한 감사"),
        RISK_ASSESSMENT("위험도 평가"),
        POLICY_REVIEW("정책 검토"),
        COMPLIANCE_CHECK("컴플라이언스 확인"),
        INCIDENT_ANALYSIS("보안 사고 분석");
        
        private final String description;
        
        AnalysisScope(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 협업 모드 열거형
     */
    public enum CollaborationMode {
        SEQUENTIAL("순차 실행"),
        PARALLEL("병렬 실행"),
        HYBRID("하이브리드");
        
        private final String description;
        
        CollaborationMode(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    public SecurityCopilotContext() {
        super(SecurityLevel.HIGH, AuditRequirement.DETAILED);
        this.securityMetadata = new HashMap<>();
        this.securityPolicies = new HashMap<>();
        this.riskThresholds = new HashMap<>();
        this.sensitiveFields = Set.of("password", "secret", "token", "key", "credential");
        initializeDefaults();
    }
    
    public SecurityCopilotContext(String userId, String sessionId) {
        super(userId, sessionId, SecurityLevel.HIGH, AuditRequirement.DETAILED);
        this.securityMetadata = new HashMap<>();
        this.securityPolicies = new HashMap<>();
        this.riskThresholds = new HashMap<>();
        this.sensitiveFields = Set.of("password", "secret", "token", "key", "credential");
        initializeDefaults();
    }
    
    private void initializeDefaults() {
        // 기본 위험 임계값 설정
        riskThresholds.put("HIGH_RISK_SCORE", "80");
        riskThresholds.put("MEDIUM_RISK_SCORE", "60");
        riskThresholds.put("EXCESSIVE_PERMISSIONS", "10");
        
        // 기본 컴플라이언스 요구사항
        complianceRequirements = List.of(
            "ISMS_P",
            "ISO_27001", 
            "SOX",
            "GDPR"
        );
    }
    
    @Override
    public String getIAMContextType() {
        return "SECURITY_COPILOT";
    }
    
    /**
     * Builder 패턴을 위한 정적 팩토리 메서드
     */
    public static class Builder {
        private final SecurityLevel securityLevel;
        private final AuditRequirement auditRequirement;
        private String userId;
        private String sessionId;
        private String securityQuery;
        private String analysisScope;
        private String priority;
        
        public Builder(SecurityLevel securityLevel, AuditRequirement auditRequirement) {
            this.securityLevel = securityLevel;
            this.auditRequirement = auditRequirement;
        }
        
        public Builder withUserId(String userId) {
            this.userId = userId;
            return this;
        }
        
        public Builder withSessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }
        
        public Builder withSecurityQuery(String query) {
            this.securityQuery = query;
            return this;
        }
        
        public Builder withAnalysisScope(String scope) {
            this.analysisScope = scope;
            return this;
        }
        
        public Builder withPriority(String priority) {
            this.priority = priority;
            return this;
        }
        
        public SecurityCopilotContext build() {
            SecurityCopilotContext context;
            if (userId != null && sessionId != null) {
                context = new SecurityCopilotContext(userId, sessionId);
            } else {
                context = new SecurityCopilotContext();
            }
            
            context.setSecurityQuery(securityQuery);
            context.setAnalysisScope(analysisScope);
            context.setPriority(priority);
            
            return context;
        }
    }
    
    /**
     * 보안 질의에서 분석 범위를 추론합니다
     */
    public AnalysisScope inferAnalysisScope() {
        if (securityQuery == null) {
            return AnalysisScope.COMPREHENSIVE;
        }
        
        String query = securityQuery.toLowerCase();
        
        if (query.contains("권한") && (query.contains("감사") || query.contains("audit"))) {
            return AnalysisScope.PERMISSION_AUDIT;
        } else if (query.contains("위험") || query.contains("risk")) {
            return AnalysisScope.RISK_ASSESSMENT;
        } else if (query.contains("정책") || query.contains("policy")) {
            return AnalysisScope.POLICY_REVIEW;
        } else if (query.contains("컴플라이언스") || query.contains("compliance")) {
            return AnalysisScope.COMPLIANCE_CHECK;
        } else if (query.contains("사고") || query.contains("incident")) {
            return AnalysisScope.INCIDENT_ANALYSIS;
        }
        
        return AnalysisScope.COMPREHENSIVE;
    }
    
    /**
     * 보안 컨텍스트가 완전한지 확인
     */
    public boolean isComplete() {
        return securityQuery != null && !securityQuery.trim().isEmpty() &&
               analysisScope != null && 
               priority != null;
    }
    
    /**
     * 보안 분석 복잡도 계산 (1-10)
     */
    public int calculateAnalysisComplexity() {
        int complexity = 1;
        
        if ("COMPREHENSIVE".equals(analysisScope)) complexity += 3;
        if (enableStudioAnalysis && enableRiskAssessment && enablePolicyGeneration) complexity += 2;
        if ("DETAILED".equals(detailLevel) || "COMPREHENSIVE".equals(detailLevel)) complexity += 2;
        if (includeRecommendations && includeActionPlan) complexity += 1;
        if (targetUsers != null && targetUsers.size() > 100) complexity += 1;
        
        return Math.min(complexity, 10);
    }
    
    /**
     * 보안 메타데이터 추가
     */
    public void addSecurityMetadata(String key, Object value) {
        if (securityMetadata == null) {
            securityMetadata = new HashMap<>();
        }
        securityMetadata.put(key, value);
    }
    
    /**
     * 보안 메타데이터 조회
     */
    @SuppressWarnings("unchecked")
    public <T> T getSecurityMetadata(String key, Class<T> type) {
        if (securityMetadata == null || !securityMetadata.containsKey(key)) {
            return null;
        }
        Object value = securityMetadata.get(key);
        return type.isInstance(value) ? (T) value : null;
    }
    
    /**
     * 컨텍스트 고유 키 생성
     */
    public String getCombinationKey() {
        return String.format("security-copilot:%s:%s:%s", 
                            analysisScope != null ? analysisScope : "unknown",
                            priority != null ? priority : "medium",
                            detailLevel);
    }
    
    /**
     * 모든 컨텍스트 데이터를 Map으로 반환
     */
    public Map<String, Object> getContextData() {
        Map<String, Object> data = new HashMap<>();
        data.put("securityQuery", securityQuery);
        data.put("analysisScope", analysisScope);
        data.put("priority", priority);
        data.put("detailLevel", detailLevel);
        data.put("collaborationMode", collaborationMode);
        data.put("complexity", calculateAnalysisComplexity());
        data.putAll(securityMetadata);
        return data;
    }
} 