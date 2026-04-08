package io.contexa.contexacore.autonomous.saas.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.LocalDateTime;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record CalibrationProfilePackSnapshot(
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

    public CalibrationProfilePackSnapshot {
        profiles = profiles == null ? List.of() : List.copyOf(profiles);
    }

    public static CalibrationProfilePackSnapshot empty() {
        return new CalibrationProfilePackSnapshot(null, false, false, false, "DISABLED", 0L, 0L, 0L, List.of(), null);
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
            double recommendedConfidenceAdjustment,
            String recommendedActionBias,
            boolean runtimeEligible,
            String promotionState,
            List<String> guardrails,
            List<String> evidenceFacts,
            List<String> policyFacts) {

        public ProfileItem {
            recommendedActionBias = recommendedActionBias == null ? "NONE" : recommendedActionBias.trim();
            guardrails = guardrails == null ? List.of() : List.copyOf(guardrails);
            evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
            policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
        }
    }
}
