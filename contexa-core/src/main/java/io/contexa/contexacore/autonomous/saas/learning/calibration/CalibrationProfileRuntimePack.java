package io.contexa.contexacore.autonomous.saas.learning.calibration;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Internal runtime DTO consumed by calibration application paths.
 */
public record CalibrationProfileRuntimePack(
        String tenantId,
        boolean runtimeReady,
        List<RuntimeCalibrationItem> profiles,
        LocalDateTime generatedAt) {

    public CalibrationProfileRuntimePack {
        profiles = profiles == null ? List.of() : List.copyOf(profiles);
    }

    public static CalibrationProfileRuntimePack empty() {
        return new CalibrationProfileRuntimePack(null, false, List.of(), null);
    }

    public record RuntimeCalibrationItem(
            String profileKey,
            String profileVersion,
            String scenarioClass,
            LearningArtifactMetadata metadata,
            long sampleSize,
            long operatorReviewedOutcomeCount,
            double falsePositiveRate,
            double falseNegativeRate,
            double challengeOverfireRate,
            double allowUnderfireRate,
            double recommendedConfidenceAdjustment,
            String recommendedActionBias,
            List<String> evidenceFacts,
            List<String> policyFacts) {

        public RuntimeCalibrationItem {
            metadata = metadata == null ? LearningArtifactMetadata.collecting() : metadata;
            recommendedActionBias = recommendedActionBias == null ? "NONE" : recommendedActionBias.trim();
            evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
            policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
        }
    }
}
