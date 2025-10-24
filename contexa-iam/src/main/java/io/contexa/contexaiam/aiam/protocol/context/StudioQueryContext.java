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
 * Authorization Studio 자연어 질의를 위한 특화된 IAM 컨텍스트
 * 
 * 자연어 질의를 통한 권한 구조 분석에 필요한 모든 컨텍스트 정보를 포함
 * 
 * 지원하는 질의 유형:
 * - 권한 보유자 조회: "해당 부서에서 누가 고객 데이터를 삭제할 수 있나요?"
 * - 접근 불가 원인 분석: "특정 사용자가 왜 회계 시스템에 접근할 수 없죠?"
 * - 팀/그룹 권한 분석: "해당 팀 권한을 분석해주세요"
 * - 리소스 접근자 분석: "이 API를 누가 호출할 수 있나요?"
 */
@Getter
@Setter
public class StudioQueryContext extends IAMContext {
    
    // 질의 정보
    private String naturalLanguageQuery;
    private String queryLanguage = "ko"; // 기본값: 한국어
    private String queryType; // WHO, WHAT, WHEN, HOW 중 하나
    private String entityType; // USER, RESOURCE, PERMISSION, ROLE 중 하나
    private String[] extractedEntities; // 추출된 엔티티들
    private int confidenceScore; // AI 분석 신뢰도
    private Map<String, Object> queryMetadata; // 질의 관련 메타데이터
    
    // 조직 구조 정보
    private String organizationStructure; // 조직도 정보
    private List<String> availableTeams;
    private List<String> availableGroups;
    private Map<String, Object> businessContext;
    
    // 권한 구조 정보
    private List<String> availableRoles;
    private List<String> availablePermissions;
    private List<String> availableResources;
    private Map<String, Set<String>> rolePermissionMap;
    private Map<String, Set<String>> userRoleMap;
    private Map<String, Set<String>> groupMemberMap;
    
    // 분석 설정
    private boolean includeVisualization = true;
    private boolean includeRecommendations = true;
    private int maxResultCount = 50;
    private String detailLevel = "DETAILED"; // SUMMARY, DETAILED, COMPREHENSIVE
    
    // 보안 및 감사
    private boolean sensitiveDataIncluded = false;
    private Set<String> excludedSensitiveFields;
    
    /**
     * 질의 타입 열거형
     */
    public enum QueryType {
        WHO_CAN("누가 ~할 수 있는가"),
        WHY_CANNOT("왜 ~할 수 없는가"),
        ANALYZE_PERMISSIONS("권한 분석"),
        ACCESS_PATH("접근 경로 분석"),
        IMPACT_ANALYSIS("영향 분석"),
        COMPLIANCE_CHECK("컴플라이언스 확인");
        
        private final String description;
        
        QueryType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 질의 범위 열거형
     */
    public enum QueryScope {
        USER("개별 사용자"),
        GROUP("그룹/팀"),
        ROLE("역할"),
        PERMISSION("권한"),
        RESOURCE("리소스"),
        ORGANIZATION("조직 전체");
        
        private final String description;
        
        QueryScope(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    public StudioQueryContext() {
        super(SecurityLevel.STANDARD, AuditRequirement.BASIC);
        this.businessContext = new HashMap<>();
        this.excludedSensitiveFields = Set.of("password", "secret", "token", "key");
        this.queryMetadata = new HashMap<>();
    }
    
    public StudioQueryContext(String userId, String sessionId) {
        super(userId, sessionId, SecurityLevel.STANDARD, AuditRequirement.BASIC);
        this.businessContext = new HashMap<>();
        this.excludedSensitiveFields = Set.of("password", "secret", "token", "key");
        this.queryMetadata = new HashMap<>();
    }
    
    @Override
    public String getIAMContextType() {
        return "STUDIO_QUERY";
    }
    
    /**
     * Builder 패턴을 위한 정적 팩토리 메서드
     */
    public static class Builder {
        private final SecurityLevel securityLevel;
        private final AuditRequirement auditRequirement;
        private String userId;
        private String sessionId;
        private String naturalLanguageQuery;
        private String queryType;
        private String entityType;
        
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
        
        public Builder withNaturalLanguageQuery(String query) {
            this.naturalLanguageQuery = query;
            return this;
        }
        
        public Builder withQueryType(String queryType) {
            this.queryType = queryType;
            return this;
        }
        
        public Builder withEntityType(String entityType) {
            this.entityType = entityType;
            return this;
        }
        
        public StudioQueryContext build() {
            StudioQueryContext context;
            if (userId != null && sessionId != null) {
                context = new StudioQueryContext(userId, sessionId);
            } else {
                context = new StudioQueryContext();
            }
            
            context.setNaturalLanguageQuery(naturalLanguageQuery);
            context.setQueryType(queryType);
            context.setEntityType(entityType);
            
            return context;
        }
    }
    
    /**
     * 자연어 질의에서 QueryType을 추론합니다
     */
    public QueryType inferQueryType() {
        if (naturalLanguageQuery == null) {
            return null;
        }
        
        String query = naturalLanguageQuery.toLowerCase();
        
        if (query.contains("누가") || query.contains("who can")) {
            return QueryType.WHO_CAN;
        } else if (query.contains("왜") || query.contains("why cannot")) {
            return QueryType.WHY_CANNOT;
        } else if (query.contains("분석") || query.contains("analyze")) {
            return QueryType.ANALYZE_PERMISSIONS;
        } else if (query.contains("경로") || query.contains("path") || query.contains("어떻게")) {
            return QueryType.ACCESS_PATH;
        } else if (query.contains("영향") || query.contains("impact")) {
            return QueryType.IMPACT_ANALYSIS;
        } else if (query.contains("컴플라이언스") || query.contains("compliance") || query.contains("규정")) {
            return QueryType.COMPLIANCE_CHECK;
        }
        
        return QueryType.ANALYZE_PERMISSIONS; // 기본값
    }
    
    /**
     * 자연어 질의에서 QueryScope를 추론합니다
     */
    public QueryScope inferQueryScope() {
        if (naturalLanguageQuery == null) {
            return null;
        }
        
        String query = naturalLanguageQuery.toLowerCase();
        
        if (query.contains("팀") || query.contains("그룹") || query.contains("team") || query.contains("group")) {
            return QueryScope.GROUP;
        } else if (query.contains("역할") || query.contains("role")) {
            return QueryScope.ROLE;
        } else if (query.contains("권한") || query.contains("permission")) {
            return QueryScope.PERMISSION;
        } else if (query.contains("리소스") || query.contains("resource") || query.contains("시스템") || query.contains("api")) {
            return QueryScope.RESOURCE;
        } else if (query.contains("조직") || query.contains("organization") || query.contains("전체")) {
            return QueryScope.ORGANIZATION;
        }
        
        return QueryScope.USER; // 기본값
    }
    
    /**
     * 컨텍스트가 완전한지 검증합니다
     */
    public boolean isComplete() {
        return naturalLanguageQuery != null && 
               !naturalLanguageQuery.trim().isEmpty() &&
               getOrganizationId() != null;
    }
    
    /**
     * 질의 복잡도를 계산합니다 (AI 처리 시간 예측용)
     */
    public int calculateQueryComplexity() {
        int complexity = 1; // 기본 복잡도
        
        if (naturalLanguageQuery != null) {
            complexity += naturalLanguageQuery.length() / 50; // 문자 길이 기반
        }
        
        if (availableRoles != null) complexity += availableRoles.size() / 10;
        if (availablePermissions != null) complexity += availablePermissions.size() / 10;
        if (availableResources != null) complexity += availableResources.size() / 10;
        
        if (includeVisualization) complexity += 2;
        if (includeRecommendations) complexity += 3;
        if ("COMPREHENSIVE".equals(detailLevel)) complexity += 5;
        
        return Math.min(complexity, 20); // 최대 복잡도 제한
    }
    
    /**
     * 질의 메타데이터 추가
     */
    public void addQueryMetadata(String key, Object value) {
        this.queryMetadata.put(key, value);
    }
    
    /**
     * 질의 메타데이터 조회
     */
    @SuppressWarnings("unchecked")
    public <T> T getQueryMetadata(String key, Class<T> type) {
        Object value = queryMetadata.get(key);
        return type.isInstance(value) ? (T) value : null;
    }
    
    /**
     * 16가지 조합 식별용 키 생성
     */
    public String getCombinationKey() {
        if (queryType != null && entityType != null) {
            return queryType + "_" + entityType;
        }
        return "UNKNOWN";
    }
    
    /**
     * 모든 컨텍스트 데이터 반환
     */
    public Map<String, Object> getContextData() {
        Map<String, Object> data = new HashMap<>();
        data.put("naturalLanguageQuery", naturalLanguageQuery);
        data.put("queryType", queryType);
        data.put("entityType", entityType);
        data.put("extractedEntities", extractedEntities);
        data.put("confidenceScore", confidenceScore);
        data.put("combinationKey", getCombinationKey());
        data.putAll(queryMetadata);
        data.putAll(getAllMetadata());
        data.putAll(getAllIAMMetadata());
        return data;
    }
} 