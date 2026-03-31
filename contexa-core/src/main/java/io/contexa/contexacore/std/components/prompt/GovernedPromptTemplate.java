package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

public interface GovernedPromptTemplate extends PromptTemplate {

    PromptGovernanceDescriptor getPromptGovernanceDescriptor();

    default PromptExecutionMetadata buildPromptExecutionMetadata(
            AIRequest<? extends DomainContext> request,
            String systemPrompt,
            String userPrompt) {
        return buildPromptExecutionMetadata(systemPrompt, userPrompt);
    }

    default PromptExecutionMetadata buildPromptExecutionMetadata(String systemPrompt, String userPrompt) {
        return PromptGovernanceSupport.buildExecutionMetadata(getPromptGovernanceDescriptor(), systemPrompt, userPrompt);
    }
}
