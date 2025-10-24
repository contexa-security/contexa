package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.domain.context.IAMContext;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

/**
 * 리소스 네이밍 AI 진단을 위한 특화된 IAM 컨텍스트
 * 리소스 친화적 이름 생성에 필요한 모든 컨텍스트 정보를 포함
 */
@Getter
@Setter
public class ResourceNamingContext extends IAMContext {
    
    private List<Map<String, String>> resourceBatch;
    private Map<String, Object> namingRules;
    private String organizationNamingConvention;
    private boolean allowKoreanNames;
    private boolean useBusinessContext;
    
    public ResourceNamingContext(SecurityLevel securityLevel, AuditRequirement auditRequirement) {
        super(securityLevel, auditRequirement);
        this.allowKoreanNames = true;
        this.useBusinessContext = true;
    }
    
    public ResourceNamingContext(String userId, String sessionId, SecurityLevel securityLevel, AuditRequirement auditRequirement) {
        super(userId, sessionId, securityLevel, auditRequirement);
        this.allowKoreanNames = true;
        this.useBusinessContext = true;
    }
    
    @Override
    public String getIAMContextType() {
        return "RESOURCE_NAMING";
    }
    
    /**
     * 리소스 네이밍에 필요한 모든 컨텍스트가 완전한지 확인합니다
     * @return 완전성 여부
     */
    public boolean isComplete() {
        return resourceBatch != null && !resourceBatch.isEmpty();
    }
    
    /**
     * 네이밍 복잡도를 계산합니다
     * @return 복잡도 점수 (1-10)
     */
    public int calculateComplexity() {
        int complexity = 1;
        
        if (resourceBatch != null) {
            complexity += Math.min(resourceBatch.size() / 10, 3);
        }
        
        if (namingRules != null && !namingRules.isEmpty()) {
            complexity += 2;
        }
        
        if (organizationNamingConvention != null && !organizationNamingConvention.isEmpty()) {
            complexity += 1;
        }
        
        if (useBusinessContext) {
            complexity += 1;
        }
        
        return Math.min(complexity, 10);
    }
    
    // Builder 패턴 지원
    public static class Builder {
        private final ResourceNamingContext context;
        
        public Builder(SecurityLevel securityLevel, AuditRequirement auditRequirement) {
            this.context = new ResourceNamingContext(securityLevel, auditRequirement);
        }
        
        public Builder(String userId, String sessionId, SecurityLevel securityLevel, AuditRequirement auditRequirement) {
            this.context = new ResourceNamingContext(userId, sessionId, securityLevel, auditRequirement);
        }
        
        public Builder withResourceBatch(List<Map<String, String>> resourceBatch) {
            context.resourceBatch = resourceBatch;
            return this;
        }
        
        public Builder withNamingRules(Map<String, Object> namingRules) {
            context.namingRules = namingRules;
            return this;
        }
        
        public Builder withOrganizationNamingConvention(String convention) {
            context.organizationNamingConvention = convention;
            return this;
        }
        
        public Builder withKoreanNames(boolean allowKoreanNames) {
            context.allowKoreanNames = allowKoreanNames;
            return this;
        }
        
        public Builder withBusinessContext(boolean useBusinessContext) {
            context.useBusinessContext = useBusinessContext;
            return this;
        }
        
        public Builder withOrganizationId(String organizationId) {
            context.setOrganizationId(organizationId);
            return this;
        }
        
        public Builder withTenantId(String tenantId) {
            context.setTenantId(tenantId);
            return this;
        }
        
        public ResourceNamingContext build() {
            return context;
        }
    }
    
    @Override
    public String toString() {
        return String.format("ResourceNamingContext{id='%s', resources=%d, complexity=%d, allowKorean=%b}", 
                getContextId(), 
                resourceBatch != null ? resourceBatch.size() : 0,
                calculateComplexity(),
                allowKoreanNames);
    }
} 