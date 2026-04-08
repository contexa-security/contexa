package io.contexa.contexacore.autonomous.saas.learning.prompt;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactGuardrail;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Assembly input that combines prompt presentation experiment output with bias risk assessment.
 */
public record PromptPresentationPackCandidate(
        PromptPresentationExperimentResult experimentResult,
        PromptBiasRiskAssessment biasRiskAssessment,
        LearningArtifactMetadata metadata,
        List<String> policyFacts) {

    public PromptPresentationPackCandidate {
        experimentResult = Objects.requireNonNull(experimentResult, "experimentResult is required");
        biasRiskAssessment = Objects.requireNonNull(biasRiskAssessment, "biasRiskAssessment is required");
        metadata = metadata == null ? defaultMetadata(experimentResult, biasRiskAssessment) : metadata;
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }

    public static PromptPresentationPackCandidate from(
            PromptPresentationExperimentResult experimentResult,
            PromptBiasRiskAssessment biasRiskAssessment) {
        return new PromptPresentationPackCandidate(
                experimentResult,
                biasRiskAssessment,
                defaultMetadata(experimentResult, biasRiskAssessment),
                mergePolicyFacts(experimentResult, biasRiskAssessment));
    }

    private static LearningArtifactMetadata defaultMetadata(
            PromptPresentationExperimentResult experimentResult,
            PromptBiasRiskAssessment assessment) {
        LearningArtifactReleaseState releaseState = assessment.blocksPromotion()
                ? LearningArtifactReleaseState.REVIEW_ONLY
                : LearningArtifactReleaseState.SHADOW_READY;
        List<LearningArtifactGuardrail> guardrails = new ArrayList<>();
        if (assessment.biasRiskState() == PromptBiasRiskState.MODERATE) {
            guardrails.add(new LearningArtifactGuardrail(
                    "PROMPT_BIAS_MODERATE",
                    "Prompt presentation pattern remains promotable but carries moderate presentation-bias risk.",
                    false));
        }
        int blockingIndex = 1;
        for (String reason : assessment.blockingReasons()) {
            guardrails.add(new LearningArtifactGuardrail("PROMPT_BIAS_BLOCK_" + blockingIndex++, reason, true));
        }
        return new LearningArtifactMetadata(
                releaseState,
                new LearningArtifactMetrics(
                        experimentResult.sampleSize(),
                        ratio(experimentResult.operatorReviewedOutcomeCount(), experimentResult.sampleSize()),
                        ratio(experimentResult.falsePositiveOutcomeCount(), experimentResult.sampleSize()),
                        0.0d,
                        assessment.falsePositiveRate(),
                        assessment.falseNegativeRate()),
                guardrails);
    }

    private static List<String> mergePolicyFacts(
            PromptPresentationExperimentResult experimentResult,
            PromptBiasRiskAssessment assessment) {
        List<String> merged = new ArrayList<>();
        merged.addAll(experimentResult.policyFacts());
        merged.addAll(assessment.policyFacts());
        return List.copyOf(merged.stream().distinct().toList());
    }

    private static double ratio(long numerator, long denominator) {
        if (denominator <= 0L) {
            return 0.0d;
        }
        return (double) numerator / (double) denominator;
    }
}