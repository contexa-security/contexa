package io.contexa.contexacore.autonomous.saas.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.LocalDateTime;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record DecisionQualityProfileSnapshot(
        String tenantId,
        boolean featureEnabled,
        boolean sharingEnabled,
        boolean runtimeReady,
        String promotionState,
        long promotedProfileCount,
        long candidateProfileCount,
        long collectingProfileCount,
        List<ProfileItem> profiles,
        LocalDateTime generatedAt) {

    public DecisionQualityProfileSnapshot {
        profiles = profiles == null ? List.of() : List.copyOf(profiles);
    }

    public static DecisionQualityProfileSnapshot empty() {
        return new DecisionQualityProfileSnapshot(null, false, false, false, "DISABLED", 0L, 0L, 0L, List.of(), null);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ProfileItem(
            String profileKey,
            String profileVersion,
            String scenarioClass,
            long sampleSize,
            long operatorReviewedOutcomeCount,
            double falsePositiveRate,
            double falseNegativeRate,
            double challengeOverfireRate,
            double allowUnderfireRate,
            boolean runtimeEligible,
            String promotionState,
            List<String> guardrails,
            List<String> evidenceFacts,
            List<String> policyFacts) {

        public ProfileItem {
            guardrails = guardrails == null ? List.of() : List.copyOf(guardrails);
            evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
            policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
        }
    }
}
