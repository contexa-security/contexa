package io.contexa.contexacore.autonomous.saas.learning.release;
import java.util.List;
/**
 * Input signal set for resolving a runtime artifact conflict.
 */
public record LearningArtifactRuntimeConflictInput(
        boolean localTruthOverrode,
        boolean localBaselineEstablished,
        boolean promptBiasRiskHigh,
        double evidenceCoverageRate,
        double falsePositiveRegressionRate,
        int repeatedConflictCount,
        int operatorRegressionCount,
        String reason,
        List<String> facts) {
    public LearningArtifactRuntimeConflictInput {
        evidenceCoverageRate = Double.isFinite(evidenceCoverageRate)
                ? Math.max(0.0d, Math.min(1.0d, evidenceCoverageRate))
                : 0.0d;
        falsePositiveRegressionRate = Double.isFinite(falsePositiveRegressionRate)
                ? Math.max(0.0d, Math.min(1.0d, falsePositiveRegressionRate))
                : 0.0d;
        repeatedConflictCount = Math.max(0, repeatedConflictCount);
        operatorRegressionCount = Math.max(0, operatorRegressionCount);
        facts = facts == null ? List.of() : List.copyOf(facts);
    }
}
