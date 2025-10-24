package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.domain.context.IAMContext;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;

/**
 * 권한 거버넌스 분석을 위한 특화된 IAM 컨텍스트
 * 
 * 시스템 전체 권한 분포와 사용 현황을 분석하여 잠재적 이상 징후를 탐지
 * 예방적 보안을 구현하여 위협이 발생하기 전에 시스템이 가진 잠재적 위험 요소를 AI가 미리 찾아내어 보고
 * 
 * 지원하는 권한 거버넌스 분석 유형:
 * - 권한 배분 최적화: "우리 시스템의 권한 배분 상태가 전반적으로 건강하고 최적화되어 있는가?"
 * - 과도한 권한 탐지: "과도한 권한을 가진 사용자를 찾아줘"
 * - 미사용 권한 식별: "사용하지 않는 권한이 있나?"
 * - 권한 상속 경로 추적: "권한 상속 구조가 올바른가?"
 */
@Getter
@Setter
public class AccessGovernanceContext extends IAMContext {
    
    // 권한 거버넌스 분석 정보
    private String auditScope;            // "ALL_USERS" | "GROUP:<ID>" | "ROLE:<ID>"
    private String analysisType;          // COMPREHENSIVE, PERMISSION_AUDIT, ROLE_OPTIMIZATION, SOD_VIOLATION
    private String priority;              // HIGH, MEDIUM, LOW
    private String queryLanguage = "ko";
    private Map<String, Object> governanceMetadata;
    
    // 분석 대상 범위
    private List<String> targetUsers;
    private List<String> targetRoles;
    private List<String> targetGroups;
    private List<String> targetResources;
    private List<String> targetPermissions;
    private Set<String> excludedEntities;
    
    // 권한 거버넌스 정책 정보
    private Map<String, Object> governancePolicies;
    private List<String> complianceRequirements;
    private Map<String, String> riskThresholds;
    
    // 분석 설정
    private boolean enableDormantPermissionAnalysis = true;
    private boolean enableExcessivePermissionDetection = true;
    private boolean enableSodViolationCheck = true;
    private boolean enableRoleOptimization = true;
    private int maxExecutionTimeSeconds = 300;
    private String analysisMode = "COMPREHENSIVE"; // SUMMARY, DETAILED, COMPREHENSIVE
    
    // 결과 설정
    private boolean includeRecommendations = true;
    private boolean includeRiskScore = true;
    private boolean includeActionPlan = true;
    private int maxFindings = 20;
    
    // 보안 제약사항
    private boolean includeSensitiveData = false;
    private Set<String> sensitiveFields;
    private String dataClassification = "INTERNAL"; // PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    
    // 권한 매트릭스 데이터 (ContextRetriever에서 채워짐)
    private String fullAccessMatrixData;
    private Map<String, Object> permissionMatrix;
    private Map<String, Object> roleMatrix;
    private Map<String, Object> userMatrix;
    
    /**
     * 권한 거버넌스 분석 범위 열거형
     */
    public enum AnalysisType {
        COMPREHENSIVE("포괄적 권한 거버넌스 분석"),
        PERMISSION_AUDIT("권한 감사"),
        ROLE_OPTIMIZATION("역할 최적화"),
        SOD_VIOLATION("업무 분리 위반 검사"),
        DORMANT_PERMISSION("미사용 권한 분석"),
        EXCESSIVE_PERMISSION("과도한 권한 탐지");
        
        private final String description;
        
        AnalysisType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 분석 모드 열거형
     */
    public enum AnalysisMode {
        SUMMARY("요약 분석"),
        DETAILED("상세 분석"),
        COMPREHENSIVE("포괄적 분석");
        
        private final String description;
        
        AnalysisMode(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    public AccessGovernanceContext() {
        super(SecurityLevel.HIGH, AuditRequirement.DETAILED);
        this.governanceMetadata = new HashMap<>();
        this.governancePolicies = new HashMap<>();
        this.riskThresholds = new HashMap<>();
        this.sensitiveFields = Set.of("password", "secret", "token", "key", "credential");
        initializeDefaults();
    }
    
    public AccessGovernanceContext(String userId, String sessionId) {
        super(userId, sessionId, SecurityLevel.HIGH, AuditRequirement.DETAILED);
        this.governanceMetadata = new HashMap<>();
        this.governancePolicies = new HashMap<>();
        this.riskThresholds = new HashMap<>();
        this.sensitiveFields = Set.of("password", "secret", "token", "key", "credential");
        initializeDefaults();
    }
    
    private void initializeDefaults() {
        this.auditScope = "ALL_USERS";
        this.analysisType = AnalysisType.COMPREHENSIVE.name();
        this.priority = "MEDIUM";
        this.complianceRequirements = List.of("SOX", "GDPR", "ISO27001");
        this.riskThresholds.put("excessive_permission", "0.8");
        this.riskThresholds.put("dormant_permission", "0.6");
        this.riskThresholds.put("sod_violation", "0.9");
    }
    
    /**
     * 권한 거버넌스 메타데이터 추가
     */
    public void addGovernanceMetadata(String key, Object value) {
        this.governanceMetadata.put(key, value);
    }
    
    /**
     * 권한 거버넌스 정책 추가
     */
    public void addGovernancePolicy(String key, Object value) {
        this.governancePolicies.put(key, value);
    }
    
    /**
     * 위험 임계값 설정
     */
    public void setRiskThreshold(String riskType, String threshold) {
        this.riskThresholds.put(riskType, threshold);
    }
    
    @Override
    public String getIAMContextType() {
        return "ACCESS_GOVERNANCE";
    }
} 