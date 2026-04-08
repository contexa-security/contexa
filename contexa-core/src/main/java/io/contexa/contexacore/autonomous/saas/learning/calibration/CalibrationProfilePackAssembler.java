package io.contexa.contexacore.autonomous.saas.learning.calibration;

import io.contexa.contexacore.autonomous.saas.dto.CalibrationProfilePackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactGuardrail;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactLifecycle;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;

/**
 * Assembles calibration-learning results into transport snapshots and runtime DTOs.
 */
public class CalibrationProfilePackAssembler {

    private static final String DEFAULT_VERSION = "1.0.0";

    public CalibrationProfilePackSnapshot assembleSnapshot(
            String tenantId,
            boolean featureEnabled,
            boolean sharingEnabled,
            List<CalibrationProfilePackCandidate> candidates) {
        List<CalibrationProfilePackCandidate> safeCandidates = candidates == null ? List.of() : List.copyOf(candidates);
        if (safeCandidates.isEmpty()) {
            return CalibrationProfilePackSnapshot.empty();
        }

        List<CalibrationProfilePackSnapshot.ProfileItem> items = safeCandidates.stream()
                .map(this::toSnapshotItem)
                .toList();

        return new CalibrationProfilePackSnapshot(
                tenantId,
                featureEnabled,
                sharingEnabled,
                safeCandidates.stream().anyMatch(candidate -> candidate.metadata().isRuntimeEligible()),
                summarizePromotionState(safeCandidates),
                safeCandidates.stream().filter(candidate -> candidate.metadata().isPromoted()).count(),
                safeCandidates.stream().filter(candidate -> !candidate.metadata().isCollecting()).count(),
                safeCandidates.stream().filter(candidate -> candidate.metadata().isCollecting()).count(),
                items,
                LocalDateTime.now());
    }

    public CalibrationProfileRuntimePack assembleRuntimePack(String tenantId, List<CalibrationProfilePackCandidate> candidates) {
        List<CalibrationProfilePackCandidate> safeCandidates = candidates == null ? List.of() : List.copyOf(candidates);
        if (safeCandidates.isEmpty()) {
            return CalibrationProfileRuntimePack.empty();
        }
        List<CalibrationProfileRuntimePack.RuntimeCalibrationItem> items = safeCandidates.stream()
                .map(this::toRuntimeItem)
                .toList();
        return new CalibrationProfileRuntimePack(
                tenantId,
                safeCandidates.stream().anyMatch(candidate -> candidate.metadata().isRuntimeEligible()),
                items,
                LocalDateTime.now());
    }

    private CalibrationProfilePackSnapshot.ProfileItem toSnapshotItem(CalibrationProfilePackCandidate candidate) {
        CalibrationProfileLearningScenarioResult result = candidate.scenarioResult();
        DecisionBiasAggregationResult aggregation = result.biasAggregation();
        LearningArtifactMetadata metadata = candidate.metadata();
        return new CalibrationProfilePackSnapshot.ProfileItem(
                profileKey(result.scenarioClass()),
                DEFAULT_VERSION,
                result.scenarioClass(),
                aggregation.sampleSize(),
                aggregation.operatorReviewedOutcomeCount(),
                aggregation.falsePositiveRate(),
                aggregation.falseNegativeRate(),
                aggregation.challengeOverfireRate(),
                aggregation.allowUnderfireRate(),
                aggregation.recommendedConfidenceAdjustment(),
                aggregation.recommendedActionBias(),
                metadata.isRuntimeEligible(),
                metadata.releaseState().name(),
                metadata.guardrails().stream().map(LearningArtifactGuardrail::summary).toList(),
                result.evidenceFacts(),
                candidate.policyFacts());
    }

    private CalibrationProfileRuntimePack.RuntimeCalibrationItem toRuntimeItem(CalibrationProfilePackCandidate candidate) {
        CalibrationProfileLearningScenarioResult result = candidate.scenarioResult();
        DecisionBiasAggregationResult aggregation = result.biasAggregation();
        return new CalibrationProfileRuntimePack.RuntimeCalibrationItem(
                profileKey(result.scenarioClass()),
                DEFAULT_VERSION,
                result.scenarioClass(),
                candidate.metadata(),
                aggregation.sampleSize(),
                aggregation.operatorReviewedOutcomeCount(),
                aggregation.falsePositiveRate(),
                aggregation.falseNegativeRate(),
                aggregation.challengeOverfireRate(),
                aggregation.allowUnderfireRate(),
                aggregation.recommendedConfidenceAdjustment(),
                aggregation.recommendedActionBias(),
                result.evidenceFacts(),
                candidate.policyFacts());
    }

    private String summarizePromotionState(List<CalibrationProfilePackCandidate> candidates) {
        return candidates.stream()
                .map(CalibrationProfilePackCandidate::metadata)
                .map(LearningArtifactLifecycle::releaseState)
                .min(this::statePriority)
                .orElse(LearningArtifactReleaseState.COLLECTING)
                .name();
    }

    private int statePriority(LearningArtifactReleaseState left, LearningArtifactReleaseState right) {
        return Integer.compare(priority(left), priority(right));
    }

    private int priority(LearningArtifactReleaseState state) {
        if (state == null) {
            return Integer.MAX_VALUE;
        }
        return switch (state) {
            case PROMOTED -> 0;
            case CANARY_READY -> 1;
            case REPLAY_READY -> 2;
            case SHADOW_READY -> 3;
            case REVIEW_ONLY -> 4;
            case COLLECTING -> 5;
            case WITHDRAWN -> 6;
            case KILL_SWITCH_ACTIVE -> 7;
        };
    }

    private String profileKey(String scenarioClass) {
        if (scenarioClass == null || scenarioClass.isBlank()) {
            return "calibration-profile/unclassified";
        }
        return "calibration-profile/" + scenarioClass.trim().toLowerCase(Locale.ROOT).replace('_', '-');
    }
}
