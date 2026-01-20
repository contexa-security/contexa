package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexaiam.aiam.protocol.enums.PolicyGenerationMode;
import io.contexa.contexacommon.domain.context.IAMContext;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;
import java.util.Set;


@Getter
@Setter
public class PolicyContext extends IAMContext {
    
    private List<String> availableRoles;
    private List<String> availablePermissions;
    private List<String> availableConditionTypes;
    private List<String> availableResources;
    private Map<String, Object> currentPolicySet;
    private Set<String> businessRules;
    private String naturalLanguageQuery;
    private PolicyGenerationMode generationMode;
    private boolean allowExperimentalFeatures;
    
    public PolicyContext(SecurityLevel securityLevel, AuditRequirement auditRequirement) {
        super(securityLevel, auditRequirement);
        this.generationMode = PolicyGenerationMode.QUICK;
        this.allowExperimentalFeatures = false;
    }
    
    public PolicyContext(String userId, String sessionId, SecurityLevel securityLevel, AuditRequirement auditRequirement) {
        super(userId, sessionId, securityLevel, auditRequirement);
        this.generationMode = PolicyGenerationMode.QUICK;
        this.allowExperimentalFeatures = false;
    }
    
    @Override
    public String getIAMContextType() {
        return "POLICY";
    }
    
    
    public boolean isComplete() {
        return availableRoles != null && !availableRoles.isEmpty() &&
               availablePermissions != null && !availablePermissions.isEmpty() &&
               availableConditionTypes != null && !availableConditionTypes.isEmpty() &&
               naturalLanguageQuery != null && !naturalLanguageQuery.trim().isEmpty();
    }
    
    
    public int calculateComplexity() {
        int complexity = 1;
        
        if (availableRoles != null) complexity += Math.min(availableRoles.size() / 5, 2);
        if (availablePermissions != null) complexity += Math.min(availablePermissions.size() / 10, 2);
        if (availableConditionTypes != null) complexity += Math.min(availableConditionTypes.size() / 3, 2);
        if (businessRules != null) complexity += Math.min(businessRules.size() / 5, 2);
        if (allowExperimentalFeatures) complexity += 1;
        
        return Math.min(complexity, 10);
    }
    
    
    public boolean isStreamingRecommended() {
        return calculateComplexity() >= 6 || 
               (naturalLanguageQuery != null && naturalLanguageQuery.length() > 200) ||
               generationMode == PolicyGenerationMode.AI_ASSISTED;
    }
    
    
    public static class Builder {
        private final PolicyContext context;
        
        public Builder(SecurityLevel securityLevel, AuditRequirement auditRequirement) {
            this.context = new PolicyContext(securityLevel, auditRequirement);
        }
        
        public Builder(String userId, String sessionId, SecurityLevel securityLevel, AuditRequirement auditRequirement) {
            this.context = new PolicyContext(userId, sessionId, securityLevel, auditRequirement);
        }
        
        public Builder withAvailableRoles(List<String> roles) {
            context.availableRoles = roles;
            return this;
        }
        
        public Builder withAvailablePermissions(List<String> permissions) {
            context.availablePermissions = permissions;
            return this;
        }
        
        public Builder withAvailableConditionTypes(List<String> conditionTypes) {
            context.availableConditionTypes = conditionTypes;
            return this;
        }
        
        public Builder withAvailableResources(List<String> resources) {
            context.availableResources = resources;
            return this;
        }
        
        public Builder withCurrentPolicySet(Map<String, Object> policySet) {
            context.currentPolicySet = policySet;
            return this;
        }
        
        public Builder withBusinessRules(Set<String> businessRules) {
            context.businessRules = businessRules;
            return this;
        }
        
        public Builder withNaturalLanguageQuery(String query) {
            context.naturalLanguageQuery = query;
            return this;
        }
        
        public Builder withGenerationMode(PolicyGenerationMode mode) {
            context.generationMode = mode;
            return this;
        }
        
        public Builder withExperimentalFeatures(boolean allow) {
            context.allowExperimentalFeatures = allow;
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
        
        public PolicyContext build() {
            return context;
        }
    }
    
    @Override
    public String toString() {
        return String.format("PolicyContext{id='%s', mode=%s, roles=%d, permissions=%d, complexity=%d}", 
                getContextId(), generationMode, 
                availableRoles != null ? availableRoles.size() : 0,
                availablePermissions != null ? availablePermissions.size() : 0,
                calculateComplexity());
    }
} 