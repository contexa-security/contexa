package io.contexa.contexacore.std.components.prompt;

public interface PromptGovernanceDescriptorResolver {

    PromptGovernanceDescriptorResolution resolve(
            PromptGovernanceDescriptor fallbackDescriptor,
            PromptGovernanceResolutionContext context);

    static PromptGovernanceDescriptorResolver identity() {
        return PromptGovernanceDescriptorResolution::fallback;
    }
}
