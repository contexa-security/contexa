package io.contexa.contexacore.autonomous.saas.learning.strategy;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactGuardrail;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Qualified strategy-family candidate that can be assembled into a snapshot and a runtime DTO.
 */
public record DetectionStrategyPackCandidate(
        DetectionStrategyLearningFamilyResult familyResult,
        StrategyEvidenceQualificationDecision qualificationDecision,
        StrategyEvidenceQualificationThresholds thresholds) {

    public DetectionStrategyPackCandidate {
        familyResult = Objects.requireNonNull(familyResult, "familyResult is required");
        qualificationDecision = Objects.requireNonNull(qualificationDecision, "qualificationDecision is required");
        thresholds = Objects.requireNonNull(thresholds, "thresholds is required");
    }

    public LearningArtifactMetadata metadata() {
        LearningArtifactMetrics metrics = familyResult.metrics() == null
                ? LearningArtifactMetrics.empty()
                : familyResult.metrics();
        return new LearningArtifactMetadata(
                qualificationDecision.recommendedReleaseState(),
                metrics,
                toGuardrails(qualificationDecision.blockingReasons()));
    }

    private List<LearningArtifactGuardrail> toGuardrails(List<String> blockingReasons) {
        if (blockingReasons == null || blockingReasons.isEmpty()) {
            return List.of();
        }
        List<LearningArtifactGuardrail> guardrails = new ArrayList<>();
        for (String reason : blockingReasons) {
            guardrails.add(new LearningArtifactGuardrail(toCode(reason), reason, true));
        }
        return List.copyOf(guardrails);
    }

    private String toCode(String reason) {
        String value = reason == null ? "UNKNOWN" : reason.toUpperCase(Locale.ROOT);
        if (value.contains("OUTCOME EVIDENCE COUNT")) {
            return "MINIMUM_EVIDENCE_FLOOR";
        }
        if (value.contains("OUTCOME COVERAGE")) {
            return "OUTCOME_COVERAGE_FLOOR";
        }
        if (value.contains("HARD-NEGATIVE COVERAGE")) {
            return "HARD_NEGATIVE_COVERAGE_FLOOR";
        }
        if (value.contains("LOCAL LIFT")) {
            return "LOCAL_LIFT_FLOOR";
        }
        return "STRATEGY_EVIDENCE_GATE";
    }
}
