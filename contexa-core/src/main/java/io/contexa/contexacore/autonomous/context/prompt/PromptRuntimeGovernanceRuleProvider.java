package io.contexa.contexacore.autonomous.context.prompt;

import java.util.List;
import java.util.Map;

public interface PromptRuntimeGovernanceRuleProvider {

    List<PromptRuntimeGovernanceRule> activeRules(PromptRuntimeGovernanceRuleContext context);

    default void recordApplications(
            PromptRuntimeGovernanceRuleContext context,
            List<PromptRuntimeGovernanceRuleApplication> applications,
            String systemPromptHash,
            String userPromptHash) {
    }

    default Map<String, Object> runtimeCacheMetadata(PromptRuntimeGovernanceRuleContext context) {
        return Map.of();
    }

    static PromptRuntimeGovernanceRuleProvider none() {
        return context -> List.of();
    }
}
