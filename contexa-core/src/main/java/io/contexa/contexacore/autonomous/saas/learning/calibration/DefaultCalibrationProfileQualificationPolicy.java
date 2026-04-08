package io.contexa.contexacore.autonomous.saas.learning.calibration;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Default qualification policy for calibration profile promotion.
 */
public class DefaultCalibrationProfileQualificationPolicy implements CalibrationProfileQualificationPolicy {

    private final CalibrationProfileQualificationThresholds thresholds;

    public DefaultCalibrationProfileQualificationPolicy(CalibrationProfileQualificationThresholds thresholds) {
        this.thresholds = Objects.requireNonNull(thresholds, "thresholds is required");
    }

    @Override
    public CalibrationProfileQualificationDecision evaluate(CalibrationProfileLearningScenarioResult scenarioResult) {
        if (scenarioResult == null) {
            return new CalibrationProfileQualificationDecision(
                    false,
                    LearningArtifactReleaseState.COLLECTING,
                    List.of("Calibration scenario result is required."),
                    List.of("Qualification skipped because no calibration scenario result was provided."));
        }
        DecisionBiasAggregationResult aggregation = scenarioResult.biasAggregation() == null
                ? DecisionBiasAggregationResult.empty()
                : scenarioResult.biasAggregation();
        List<String> blockingReasons = new ArrayList<>();
        List<String> policyFacts = new ArrayList<>();
        policyFacts.add(String.format(
                Locale.ROOT,
                "Scenario=%s sampleSize=%d reviewedOutcomes=%d falsePositiveRate=%.4f falseNegativeRate=%.4f.",
                scenarioResult.scenarioClass(),
                aggregation.sampleSize(),
                aggregation.operatorReviewedOutcomeCount(),
                aggregation.falsePositiveRate(),
                aggregation.falseNegativeRate()));
        policyFacts.add(String.format(
                Locale.ROOT,
                "Thresholds minimumSample=%d minimumReviewedOutcomes=%d maxFalsePositiveRate=%.4f maxFalseNegativeRate=%.4f.",
                thresholds.minimumSampleSize(),
                thresholds.minimumReviewedOutcomeCount(),
                thresholds.maximumFalsePositiveRate(),
                thresholds.maximumFalseNegativeRate()));
        if (aggregation.sampleSize() < thresholds.minimumSampleSize()) {
            blockingReasons.add(String.format(
                    Locale.ROOT,
                    "Sample size %d is below the minimum calibration sample floor %d.",
                    aggregation.sampleSize(),
                    thresholds.minimumSampleSize()));
        }
        if (aggregation.operatorReviewedOutcomeCount() < thresholds.minimumReviewedOutcomeCount()) {
            blockingReasons.add(String.format(
                    Locale.ROOT,
                    "Reviewed outcomes %d are below the minimum reviewed outcome floor %d.",
                    aggregation.operatorReviewedOutcomeCount(),
                    thresholds.minimumReviewedOutcomeCount()));
        }
        if (aggregation.falsePositiveRate() > thresholds.maximumFalsePositiveRate()) {
            blockingReasons.add(String.format(
                    Locale.ROOT,
                    "False-positive rate %.4f exceeds the maximum accepted calibration floor %.4f.",
                    aggregation.falsePositiveRate(),
                    thresholds.maximumFalsePositiveRate()));
        }
        if (aggregation.falseNegativeRate() > thresholds.maximumFalseNegativeRate()) {
            blockingReasons.add(String.format(
                    Locale.ROOT,
                    "False-negative rate %.4f exceeds the maximum accepted calibration floor %.4f.",
                    aggregation.falseNegativeRate(),
                    thresholds.maximumFalseNegativeRate()));
        }
        boolean qualified = blockingReasons.isEmpty();
        policyFacts.add(qualified
                ? "Qualification passed. The calibration profile can advance to artifact assembly as SHADOW_READY."
                : "Qualification failed. The calibration profile must remain in COLLECTING until all floors are met.");
        return new CalibrationProfileQualificationDecision(
                qualified,
                qualified ? LearningArtifactReleaseState.SHADOW_READY : LearningArtifactReleaseState.COLLECTING,
                blockingReasons,
                policyFacts);
    }
}