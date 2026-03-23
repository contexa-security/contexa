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