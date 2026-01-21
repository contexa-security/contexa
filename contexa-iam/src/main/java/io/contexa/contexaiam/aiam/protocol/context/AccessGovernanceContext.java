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

@Getter
@Setter
public class AccessGovernanceContext extends IAMContext {

    private String auditScope;            
    private String analysisType;          
    private String priority;              
    private String queryLanguage = "ko";
    private Map<String, Object> governanceMetadata;

    private List<String> targetUsers;
    private List<String> targetRoles;
    private List<String> targetGroups;
    private List<String> targetResources;
    private List<String> targetPermissions;
    private Set<String> excludedEntities;

    private Map<String, Object> governancePolicies;
    private List<String> complianceRequirements;
    private Map<String, String> riskThresholds;

    private boolean enableDormantPermissionAnalysis = true;
    private boolean enableExcessivePermissionDetection = true;
    private boolean enableSodViolationCheck = true;
    private boolean enableRoleOptimization = true;
    private int maxExecutionTimeSeconds = 300;
    private String analysisMode = "COMPREHENSIVE"; 

    private boolean includeRecommendations = true;
    private boolean includeRiskScore = true;
    private boolean includeActionPlan = true;
    private int maxFindings = 20;

    private boolean includeSensitiveData = false;
    private Set<String> sensitiveFields;
    private String dataClassification = "INTERNAL"; 

    private String fullAccessMatrixData;
    private Map<String, Object> permissionMatrix;
    private Map<String, Object> roleMatrix;
    private Map<String, Object> userMatrix;

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

    public void addGovernanceMetadata(String key, Object value) {
        this.governanceMetadata.put(key, value);
    }

    public void addGovernancePolicy(String key, Object value) {
        this.governancePolicies.put(key, value);
    }

    public void setRiskThreshold(String riskType, String threshold) {
        this.riskThresholds.put(riskType, threshold);
    }
    
    @Override
    public String getIAMContextType() {
        return "ACCESS_GOVERNANCE";
    }
} 