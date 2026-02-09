package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexaiam.aiam.protocol.enums.PolicyGenerationMode;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Getter
@Setter
public class PolicyContext extends DomainContext {

    private List<String> availableRoles;
    private List<String> availablePermissions;
    private List<String> availableConditionTypes;
    private List<String> availableResources;
    private Map<String, Object> currentPolicySet;
    private Set<String> businessRules;
    private String naturalLanguageQuery;
    private PolicyGenerationMode generationMode;
    private boolean allowExperimentalFeatures;

    public PolicyContext() {
        super();
        this.generationMode = PolicyGenerationMode.QUICK;
        this.allowExperimentalFeatures = false;
    }

    public PolicyContext(String userId, String sessionId) {
        super(userId, sessionId);
        this.generationMode = PolicyGenerationMode.QUICK;
        this.allowExperimentalFeatures = false;
    }

    @Override
    public String getDomainType() {
        return "POLICY";
    }

    public boolean isComplete() {
        return availableRoles != null && !availableRoles.isEmpty() &&
               availablePermissions != null && !availablePermissions.isEmpty() &&
               availableConditionTypes != null && !availableConditionTypes.isEmpty() &&
               naturalLanguageQuery != null && !naturalLanguageQuery.trim().isEmpty();
    }

    public static class Builder {
        private final PolicyContext context;

        public Builder() {
            this.context = new PolicyContext();
        }

        public Builder(String userId, String sessionId) {
            this.context = new PolicyContext(userId, sessionId);
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

        public PolicyContext build() {
            return context;
        }
    }
}
