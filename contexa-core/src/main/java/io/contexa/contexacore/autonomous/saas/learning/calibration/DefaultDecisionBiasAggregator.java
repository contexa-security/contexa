package io.contexa.contexacore.autonomous.saas.learning.calibration;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Default scenario bias aggregator based on confidence band, action class, and reviewed outcome.
 */
public class DefaultDecisionBiasAggregator implements DecisionBiasAggregator {

    private static final double HIGH_CONFIDENCE_THRESHOLD = 0.85d;
    private static final double MODERATE_CONFIDENCE_THRESHOLD = 0.70d;
    private static final double MAX_CONFIDENCE_ADJUSTMENT = 0.20d;
    private static final double ACTION_BIAS_MARGIN = 0.05d;

    @Override
    public DecisionBiasAggregationResult aggregate(String scenarioClass, List<CalibrationLearningObservation> observations) {
        List<CalibrationLearningObservation> safeObservations = observations == null ? List.of() : List.copyOf(observations);
        if (safeObservations.isEmpty()) {
            return DecisionBiasAggregationResult.empty();
        }

        long sampleSize = safeObservations.size();
        long operatorReviewedOutcomeCount = 0L;
        long falsePositiveCount = 0L;
        long falseNegativeCount = 0L;
        long challengeDecisions = 0L;
        long challengeOverfires = 0L;
        long allowDecisions = 0L;
        long allowUnderfires = 0L;
        double confidenceBiasScore = 0.0d;

        Map<String, Long> actionCounts = new LinkedHashMap<>();
        Map<String, Long> confidenceBandCounts = new LinkedHashMap<>();
        Map<String, Long> reviewedOutcomeCounts = new LinkedHashMap<>();

        for (CalibrationLearningObservation observation : safeObservations) {
            if (observation == null) {
                continue;
            }
            String actionClass = actionClass(observation);
            String confidenceBand = confidenceBand(observation.decisionConfidence());
            String reviewedOutcome = reviewedOutcome(observation);
            OutcomeCategory outcomeCategory = outcomeCategory(reviewedOutcome);

            increment(actionCounts, actionClass);
            increment(confidenceBandCounts, confidenceBand);
            if (reviewedOutcome != null) {
                operatorReviewedOutcomeCount++;
                increment(reviewedOutcomeCounts, reviewedOutcome);
            }

            if (isChallengeFamily(actionClass)) {
                challengeDecisions++;
                if (outcomeCategory == OutcomeCategory.FALSE_POSITIVE || outcomeCategory == OutcomeCategory.BENIGN) {
                    challengeOverfires++;
                }
            }
            if ("ALLOW".equals(actionClass)) {
                allowDecisions++;
                if (outcomeCategory == OutcomeCategory.FALSE_NEGATIVE || outcomeCategory == OutcomeCategory.CONFIRMED_ATTACK) {
                    allowUnderfires++;
                }
            }
            if (outcomeCategory == OutcomeCategory.FALSE_POSITIVE || (isChallengeFamily(actionClass) && outcomeCategory == OutcomeCategory.BENIGN)) {
                falsePositiveCount++;
                confidenceBiasScore -= confidenceBandWeight(confidenceBand);
            }
            if (outcomeCategory == OutcomeCategory.FALSE_NEGATIVE || ("ALLOW".equals(actionClass) && outcomeCategory == OutcomeCategory.CONFIRMED_ATTACK)) {
                falseNegativeCount++;
                confidenceBiasScore += confidenceBandWeight(confidenceBand);
            }
        }

        double denominator = operatorReviewedOutcomeCount > 0L ? operatorReviewedOutcomeCount : sampleSize;
        double falsePositiveRate = ratio(falsePositiveCount, denominator);
        double falseNegativeRate = ratio(falseNegativeCount, denominator);
        double challengeOverfireRate = ratio(challengeOverfires, challengeDecisions);
        double allowUnderfireRate = ratio(allowUnderfires, allowDecisions);
        double recommendedConfidenceAdjustment = clamp((confidenceBiasScore / Math.max(1.0d, denominator)) * MAX_CONFIDENCE_ADJUSTMENT,
                -MAX_CONFIDENCE_ADJUSTMENT,
                MAX_CONFIDENCE_ADJUSTMENT);

        return new DecisionBiasAggregationResult(
                sampleSize,
                operatorReviewedOutcomeCount,
                falsePositiveCount,
                falseNegativeCount,
                falsePositiveRate,
                falseNegativeRate,
                challengeOverfireRate,
                allowUnderfireRate,
                recommendedConfidenceAdjustment,
                recommendedActionBias(falsePositiveRate, falseNegativeRate, challengeOverfireRate, allowUnderfireRate),
                aggregationFacts(scenarioClass, sampleSize, operatorReviewedOutcomeCount, actionCounts, confidenceBandCounts, reviewedOutcomeCounts,
                        falsePositiveCount, falseNegativeCount, challengeOverfireRate, allowUnderfireRate, recommendedConfidenceAdjustment));
    }

    private List<String> aggregationFacts(
            String scenarioClass,
            long sampleSize,
            long reviewedCount,
            Map<String, Long> actionCounts,
            Map<String, Long> confidenceBandCounts,
            Map<String, Long> reviewedOutcomeCounts,
            long falsePositiveCount,
            long falseNegativeCount,
            double challengeOverfireRate,
            double allowUnderfireRate,
            double recommendedConfidenceAdjustment) {
        return List.of(
                "Scenario class " + scenarioClass + " aggregated " + sampleSize + " observations with " + reviewedCount + " reviewed outcomes.",
                "Action class distribution=" + actionCounts + ".",
                "Confidence band distribution=" + confidenceBandCounts + ".",
                "Reviewed outcome distribution=" + reviewedOutcomeCounts + ".",
                "False positives=" + falsePositiveCount + ", false negatives=" + falseNegativeCount + ".",
                String.format(Locale.ROOT,
                        "Challenge overfire=%.2f, allow underfire=%.2f, recommended confidence adjustment=%.3f.",
                        challengeOverfireRate,
                        allowUnderfireRate,
                        recommendedConfidenceAdjustment));
    }

    private String recommendedActionBias(
            double falsePositiveRate,
            double falseNegativeRate,
            double challengeOverfireRate,
            double allowUnderfireRate) {
        if (allowUnderfireRate >= challengeOverfireRate + ACTION_BIAS_MARGIN
                || falseNegativeRate >= falsePositiveRate + ACTION_BIAS_MARGIN) {
            return "INCREASE_CHALLENGE";
        }
        if (challengeOverfireRate >= allowUnderfireRate + ACTION_BIAS_MARGIN
                || falsePositiveRate >= falseNegativeRate + ACTION_BIAS_MARGIN) {
            return "DECREASE_CHALLENGE";
        }
        return "NONE";
    }

    private boolean isChallengeFamily(String actionClass) {
        return "CHALLENGE".equals(actionClass) || "BLOCK".equals(actionClass);
    }

    private String actionClass(CalibrationLearningObservation observation) {
        String action = normalize(observation.originalAction());
        if (action == null) {
            action = normalize(observation.finalAction());
        }
        if (action == null) {
            return "UNKNOWN";
        }
        if (action.contains("BLOCK") || action.contains("TERMINATE") || action.contains("LOCK")) {
            return "BLOCK";
        }
        if (action.contains("CHALLENGE") || action.contains("ESCALATE")) {
            return "CHALLENGE";
        }
        if (action.contains("ALLOW") || action.contains("PASS")) {
            return "ALLOW";
        }
        return action;
    }

    private String confidenceBand(Double decisionConfidence) {
        if (decisionConfidence == null || !Double.isFinite(decisionConfidence)) {
            return "UNKNOWN";
        }
        if (decisionConfidence >= HIGH_CONFIDENCE_THRESHOLD) {
            return "HIGH";
        }
        if (decisionConfidence >= MODERATE_CONFIDENCE_THRESHOLD) {
            return "MODERATE";
        }
        return "LOW";
    }

    private double confidenceBandWeight(String confidenceBand) {
        return switch (confidenceBand) {
            case "HIGH" -> 1.0d;
            case "MODERATE" -> 0.6d;
            case "LOW" -> 0.3d;
            default -> 0.4d;
        };
    }

    private String reviewedOutcome(CalibrationLearningObservation observation) {
        String outcome = normalize(observation.operatorReviewedOutcome());
        if (outcome == null) {
            outcome = normalize(observation.finalDisposition());
        }
        if (outcome == null) {
            outcome = normalize(observation.outcomeType());
        }
        if (outcome == null) {
            outcome = normalize(observation.feedbackType());
        }
        return outcome;
    }

    private OutcomeCategory outcomeCategory(String reviewedOutcome) {
        if (reviewedOutcome == null) {
            return OutcomeCategory.UNKNOWN;
        }
        if (containsAny(reviewedOutcome, "false_negative")) {
            return OutcomeCategory.FALSE_NEGATIVE;
        }
        if (containsAny(reviewedOutcome, "false_positive", "benign", "harmless")) {
            return OutcomeCategory.FALSE_POSITIVE;
        }
        if (containsAny(reviewedOutcome, "confirmed_attack", "session_takeover", "compromised", "malicious", "incident_confirmed")) {
            return OutcomeCategory.CONFIRMED_ATTACK;
        }
        if (containsAny(reviewedOutcome, "allow", "normal")) {
            return OutcomeCategory.BENIGN;
        }
        return OutcomeCategory.OTHER;
    }

    private boolean containsAny(String value, String... candidates) {
        for (String candidate : candidates) {
            if (value.contains(candidate.toUpperCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private String normalize(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return normalized.isEmpty() ? null : normalized;
    }

    private void increment(Map<String, Long> counts, String key) {
        counts.merge(key == null ? "UNKNOWN" : key, 1L, Long::sum);
    }

    private double ratio(long numerator, long denominator) {
        if (denominator <= 0L) {
            return 0.0d;
        }
        return (double) numerator / (double) denominator;
    }

    private double ratio(long numerator, double denominator) {
        if (denominator <= 0.0d) {
            return 0.0d;
        }
        return numerator / denominator;
    }

    private double clamp(double value, double min, double max) {
        return Math.max(min, Math.min(max, value));
    }

    private enum OutcomeCategory {
        FALSE_POSITIVE,
        FALSE_NEGATIVE,
        CONFIRMED_ATTACK,
        BENIGN,
        OTHER,
        UNKNOWN
    }
}
