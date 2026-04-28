package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.Map;

public record PromptGovernanceResolutionContext(
        String registryScope,
        String promptKey,
        String templateKey,
        String tenantId,
        String resourceId,
        String resourceUrl,
        String httpMethod,
        Map<String, Object> attributes) {

    public PromptGovernanceResolutionContext {
        if (attributes == null || attributes.isEmpty()) {
            attributes = Map.of();
        }
        else {
            Map<String, Object> sanitized = new LinkedHashMap<>();
            attributes.forEach((key, value) -> {
                if (key != null && value != null) {
                    sanitized.put(key, value);
                }
            });
            attributes = Map.copyOf(sanitized);
        }
    }
}
