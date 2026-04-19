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
        return PromptGovernanceSupport.buildExecutionMetadata(
                getPromptGovernanceDescriptor(),
                PromptGovernanceSupport.resolveRequestedModelHint(request),
                systemPrompt,
                userPrompt);
    }

    default PromptExecutionMetadata buildPromptExecutionMetadata(String systemPrompt, String userPrompt) {
        return PromptGovernanceSupport.buildExecutionMetadata(getPromptGovernanceDescriptor(), systemPrompt, userPrompt);
    }

    default PromptExecutionMetadata buildPromptExecutionMetadata(
            AIRequest<? extends DomainContext> request,
            PromptViewComposition promptViewComposition) {
        PromptExecutionMetadata baseMetadata = buildPromptExecutionMetadata(
                request,
                promptViewComposition.llmSystemPrompt(),
                promptViewComposition.llmUserPrompt());
        return PromptGovernanceSupport.buildExecutionMetadata(
                baseMetadata.governanceDescriptor(),
                baseMetadata.budgetProfile(),
                baseMetadata.sectionSet(),
                baseMetadata.omittedSections(),
                baseMetadata.omissionLedger(),
                baseMetadata.duplicationInventory(),
                baseMetadata.promptEvidenceCompleteness(),
                PromptGovernanceSupport.resolveRequestedModelHint(request),
                promptViewComposition.llmSystemPrompt(),
                promptViewComposition.llmUserPrompt(),
                promptViewComposition.rawSystemPrompt(),
                promptViewComposition.rawUserPrompt(),
                promptViewComposition.compressionLedger(),
                baseMetadata.supplementalMetadata());
    }
}
