package io.contexa.contexacore.autonomous.saas.learning.roi;
/**
 * Cost model used to estimate artifact ROI.
 */
public record LearningRoiCostModel(
        double operatingCostPerAdoptedTenant,
        double detectionLiftValuePerUnit,
        double falsePositiveCostPerUnit,
        double rollbackPenaltyPerEvent) {
    public LearningRoiCostModel {
        validateFinite(operatingCostPerAdoptedTenant, "operatingCostPerAdoptedTenant");
        validateFinite(detectionLiftValuePerUnit, "detectionLiftValuePerUnit");
        validateFinite(falsePositiveCostPerUnit, "falsePositiveCostPerUnit");
        validateFinite(rollbackPenaltyPerEvent, "rollbackPenaltyPerEvent");
    }
    public static LearningRoiCostModel defaults() {
        return new LearningRoiCostModel(5.0d, 100.0d, 80.0d, 50.0d);
    }
    private void validateFinite(double value, String fieldName) {
        if (!Double.isFinite(value) || value < 0.0d) {
            throw new IllegalArgumentException(fieldName + " must be finite and non-negative");
        }
    }
}
