package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public record PromptGovernanceDescriptorResolution(
        PromptGovernanceDescriptor descriptor,
        Map<String, Object> supplementalMetadata) {

    public PromptGovernanceDescriptorResolution {
        descriptor = Objects.requireNonNull(descriptor, "descriptor");
        if (supplementalMetadata == null || supplementalMetadata.isEmpty()) {
            supplementalMetadata = Map.of();
        }
        else {
            Map<String, Object> sanitized = new LinkedHashMap<>();
            supplementalMetadata.forEach((key, value) -> {
                if (key != null && value != null) {
                    sanitized.put(key, value);
                }
            });
            supplementalMetadata = Map.copyOf(sanitized);
        }
    }

    public static PromptGovernanceDescriptorResolution fallback(
            PromptGovernanceDescriptor descriptor,
            PromptGovernanceResolutionContext context) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("registryScope", registryScope(context));
        metadata.put("governanceResolutionSource", "STATIC_PROMPT_DESCRIPTOR");
        metadata.put("promptGovernanceCacheState", "FALLBACK");
        return new PromptGovernanceDescriptorResolution(descriptor, metadata);
    }

    private static String registryScope(PromptGovernanceResolutionContext context) {
        if (context != null && context.registryScope() != null && !context.registryScope().isBlank()) {
            return context.registryScope().trim();
        }
        return "PLATFORM_GLOBAL";
    }
}
