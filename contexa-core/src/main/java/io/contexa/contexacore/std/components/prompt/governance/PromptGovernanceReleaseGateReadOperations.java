package io.contexa.contexacore.std.components.prompt.governance;


public interface PromptGovernanceReleaseGateReadOperations {

    PromptGovernanceView.PromptGovernanceReleaseGateSnapshot getPlatformSnapshot(Integer limit);

    PromptGovernanceView.PromptGovernanceReleaseGateSnapshot getSnapshot(String registryScope, Integer limit);
}