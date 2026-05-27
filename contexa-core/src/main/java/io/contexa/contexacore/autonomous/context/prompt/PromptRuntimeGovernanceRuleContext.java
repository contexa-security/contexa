package io.contexa.contexacore.autonomous.context.prompt;

import java.util.Map;

public record PromptRuntimeGovernanceRuleContext(
        String registryScope,
        String promptKey,
        String promptVersion,
        String tenantId,
        String resourceId,
        String resourceUrl,
        String httpMethod,
        Map<String, Object> attributes) {
}
