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
package io.contexa.contexacore.autonomous.saas.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.LocalDateTime;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ThreatKnowledgePackSnapshot(
        String tenantId,
        boolean featureEnabled,
        boolean sharingEnabled,
        boolean runtimeReady,
        String promotionState,
        long promotedCaseCount,
        long conditionalCaseCount,
        long restrictedCaseCount,
        List<KnowledgeCaseItem> cases,
        LocalDateTime generatedAt) {

    public ThreatKnowledgePackSnapshot {
        cases = cases == null ? List.of() : List.copyOf(cases);
    }

    public static ThreatKnowledgePackSnapshot empty() {
        return new ThreatKnowledgePackSnapshot(null, false, false, false, "DISABLED", 0, 0, 0, List.of(), null);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record KnowledgeCaseItem(
            String signalKey,
            String knowledgeKey,
            String canonicalThreatClass,
            String geoCountry,
            List<String> targetSurfaceHints,
            List<String> signalTags,
            List<String> campaignFacts,
            List<String> caseFacts,
            List<String> outcomeFacts,
            List<String> falsePositiveNotes,
            String learningStatus,
            List<String> learningFacts,
            String campaignSummary,
            String xaiSummary,
            LocalDateTime lastObservedAt,
            int affectedTenantCount,
            int observationCount,
            String caseMemoryStatus,
            List<String> caseMemoryFacts,
            String experimentStatus,
            List<String> experimentFacts,
            String reasoningMemoryStatus,
            List<String> reasoningMemoryFacts,
            String promotionState,
            String promotionSummary,
            List<String> promotionFacts) {

        public KnowledgeCaseItem {
            targetSurfaceHints = targetSurfaceHints == null ? List.of() : List.copyOf(targetSurfaceHints);
            signalTags = signalTags == null ? List.of() : List.copyOf(signalTags);
            campaignFacts = campaignFacts == null ? List.of() : List.copyOf(campaignFacts);
            caseFacts = caseFacts == null ? List.of() : List.copyOf(caseFacts);
            outcomeFacts = outcomeFacts == null ? List.of() : List.copyOf(outcomeFacts);
            falsePositiveNotes = falsePositiveNotes == null ? List.of() : List.copyOf(falsePositiveNotes);
            learningFacts = learningFacts == null ? List.of() : List.copyOf(learningFacts);
            caseMemoryFacts = caseMemoryFacts == null ? List.of() : List.copyOf(caseMemoryFacts);
            experimentFacts = experimentFacts == null ? List.of() : List.copyOf(experimentFacts);
            reasoningMemoryFacts = reasoningMemoryFacts == null ? List.of() : List.copyOf(reasoningMemoryFacts);
            promotionFacts = promotionFacts == null ? List.of() : List.copyOf(promotionFacts);
        }
    }
}