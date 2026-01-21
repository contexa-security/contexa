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

@Getter
@Setter
public class StudioQueryContext extends IAMContext {

    private String naturalLanguageQuery;
    private String queryLanguage = "ko"; 
    private String queryType; 
    private String entityType; 
    private String[] extractedEntities; 
    private int confidenceScore; 
    private Map<String, Object> queryMetadata; 

    private String organizationStructure; 
    private List<String> availableTeams;
    private List<String> availableGroups;
    private Map<String, Object> businessContext;

    private List<String> availableRoles;
    private List<String> availablePermissions;
    private List<String> availableResources;
    private Map<String, Set<String>> rolePermissionMap;
    private Map<String, Set<String>> userRoleMap;
    private Map<String, Set<String>> groupMemberMap;

    private boolean includeVisualization = true;
    private boolean includeRecommendations = true;
    private int maxResultCount = 50;
    private String detailLevel = "DETAILED"; 

    private boolean sensitiveDataIncluded = false;
    private Set<String> excludedSensitiveFields;

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
        
        return QueryType.ANALYZE_PERMISSIONS; 
    }

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
        
        return QueryScope.USER; 
    }

    public boolean isComplete() {
        return naturalLanguageQuery != null && 
               !naturalLanguageQuery.trim().isEmpty() &&
               getOrganizationId() != null;
    }

    public int calculateQueryComplexity() {
        int complexity = 1; 
        
        if (naturalLanguageQuery != null) {
            complexity += naturalLanguageQuery.length() / 50; 
        }
        
        if (availableRoles != null) complexity += availableRoles.size() / 10;
        if (availablePermissions != null) complexity += availablePermissions.size() / 10;
        if (availableResources != null) complexity += availableResources.size() / 10;
        
        if (includeVisualization) complexity += 2;
        if (includeRecommendations) complexity += 3;
        if ("COMPREHENSIVE".equals(detailLevel)) complexity += 5;
        
        return Math.min(complexity, 20); 
    }

    public void addQueryMetadata(String key, Object value) {
        this.queryMetadata.put(key, value);
    }

    @SuppressWarnings("unchecked")
    public <T> T getQueryMetadata(String key, Class<T> type) {
        Object value = queryMetadata.get(key);
        return type.isInstance(value) ? (T) value : null;
    }

    public String getCombinationKey() {
        if (queryType != null && entityType != null) {
            return queryType + "_" + entityType;
        }
        return "UNKNOWN";
    }

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