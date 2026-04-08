package io.contexa.contexacore.autonomous.tiered.service.calibration;

import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileRuntimePack;

import java.util.Comparator;

/**
 * Selects the strongest runtime calibration profile for a resolved scenario class.
 */
public class CalibrationProfileSelector {

    public CalibrationProfileRuntimePack.RuntimeCalibrationItem select(
            CalibrationProfileRuntimePack runtimePack,
            String scenarioClass) {
        if (runtimePack == null || !runtimePack.runtimeReady() || runtimePack.profiles().isEmpty()) {
            return null;
        }
        if (scenarioClass == null || scenarioClass.isBlank()) {
            return null;
        }
        return runtimePack.profiles().stream()
                .filter(item -> item != null
                        && item.metadata() != null
                        && item.metadata().isRuntimeEligible()
                        && !item.metadata().hasBlockingGuardrails()
                        && scenarioClass.equals(item.scenarioClass()))
                .max(Comparator
                        .comparingLong(CalibrationProfileRuntimePack.RuntimeCalibrationItem::sampleSize)
                        .thenComparingLong(CalibrationProfileRuntimePack.RuntimeCalibrationItem::operatorReviewedOutcomeCount))
                .orElse(null);
    }
}