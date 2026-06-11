/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
