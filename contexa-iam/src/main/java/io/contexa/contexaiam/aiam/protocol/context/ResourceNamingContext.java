package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
public class ResourceNamingContext extends DomainContext {

    private List<Map<String, String>> resourceBatch;
    private Map<String, Object> namingRules;
    private String organizationNamingConvention;
    private boolean allowKoreanNames;
    private boolean useBusinessContext;

    public ResourceNamingContext() {
        super();
        this.allowKoreanNames = true;
        this.useBusinessContext = true;
    }

    public ResourceNamingContext(String userId, String sessionId) {
        super(userId, sessionId);
        this.allowKoreanNames = true;
        this.useBusinessContext = true;
    }

    @Override
    public String getDomainType() {
        return "RESOURCE_NAMING";
    }

    public boolean isComplete() {
        return resourceBatch != null && !resourceBatch.isEmpty();
    }

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

    public static class Builder {
        private final ResourceNamingContext context;

        public Builder() {
            this.context = new ResourceNamingContext();
        }

        public Builder(String userId, String sessionId) {
            this.context = new ResourceNamingContext(userId, sessionId);
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
