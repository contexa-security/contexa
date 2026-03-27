package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;

public interface GovernedPromptTemplate extends PromptTemplate {

    PromptGovernanceDescriptor getPromptGovernanceDescriptor();

    default PromptExecutionMetadata buildPromptExecutionMetadata(String systemPrompt, String userPrompt) {
        return PromptGovernanceSupport.buildExecutionMetadata(getPromptGovernanceDescriptor(), systemPrompt, userPrompt);
    }
}
