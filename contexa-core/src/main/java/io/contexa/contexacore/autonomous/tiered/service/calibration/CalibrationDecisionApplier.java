package io.contexa.contexacore.autonomous.tiered.service.calibration;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileRuntimePack;
import io.contexa.contexacore.autonomous.saas.learning.calibration.ScenarioClassResolution;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Applies runtime calibration conservatively after prompt and autonomy decisions are already produced.
 */
public class CalibrationDecisionApplier {

    public SecurityDecision apply(
            SecurityDecision decision,
            ScenarioClassResolution scenarioResolution,
            CalibrationProfileRuntimePack.RuntimeCalibrationItem profile) {
        if (decision == null || scenarioResolution == null || !scenarioResolution.isResolved() || profile == null) {
            return decision;
        }

        boolean localConstraintLocked = Boolean.TRUE.equals(decision.getAutonomyConstraintApplied());
        ZeroTrustAction originalAutonomousAction = decision.resolveAutonomousAction();
        Double baseConfidence = decision.getConfidence() != null ? decision.getConfidence() : decision.resolveAuditConfidence();

        double appliedConfidenceAdjustment = 0.0d;
        boolean confidenceChanged = false;
        if (!localConstraintLocked && baseConfidence != null && Double.isFinite(profile.recommendedConfidenceAdjustment())) {
            double adjustedConfidence = clamp(baseConfidence + profile.recommendedConfidenceAdjustment(), 0.0d, 1.0d);
            if (Double.compare(adjustedConfidence, baseConfidence) != 0) {
                decision.setConfidence(adjustedConfidence);
                appliedConfidenceAdjustment = adjustedConfidence - baseConfidence;
                confidenceChanged = true;
            }
        }

        ZeroTrustAction adjustedAutonomousAction = originalAutonomousAction;
        boolean actionChanged = false;
        if (!localConstraintLocked) {
            adjustedAutonomousAction = applyActionBias(originalAutonomousAction, decision.getAction(), profile.recommendedActionBias());
            actionChanged = adjustedAutonomousAction != originalAutonomousAction;
            if (actionChanged) {
                decision.setAutonomousAction(adjustedAutonomousAction);
            }
        }

        boolean calibrationApplied = confidenceChanged || actionChanged;
        List<String> reasons = buildReasons(scenarioResolution, profile, localConstraintLocked, confidenceChanged, actionChanged, appliedConfidenceAdjustment, adjustedAutonomousAction);
        decision.setCalibrationApplied(calibrationApplied);
        decision.setCalibrationProfileKey(profile.profileKey());
        decision.setCalibrationScenarioClass(scenarioResolution.scenarioClass());
        decision.setCalibrationConfidenceAdjustment(appliedConfidenceAdjustment);
        decision.setCalibrationActionBias(profile.recommendedActionBias());
        decision.setCalibrationReasons(reasons);
        decision.setCalibrationSummary(buildSummary(profile, scenarioResolution.scenarioClass(), calibrationApplied, localConstraintLocked, appliedConfidenceAdjustment, actionChanged));
        return decision;
    }

    private List<String> buildReasons(
            ScenarioClassResolution scenarioResolution,
            CalibrationProfileRuntimePack.RuntimeCalibrationItem profile,
            boolean localConstraintLocked,
            boolean confidenceChanged,
            boolean actionChanged,
            double appliedConfidenceAdjustment,
            ZeroTrustAction adjustedAutonomousAction) {
        Set<String> reasons = new LinkedHashSet<>();
        reasons.addAll(scenarioResolution.resolutionFacts());
        if (localConstraintLocked) {
            reasons.add("Local autonomy constraint retained the final runtime action.");
        }
        if (confidenceChanged) {
            reasons.add(String.format(Locale.ROOT,
                    "Calibration adjusted effective confidence by %.3f.",
                    appliedConfidenceAdjustment));
        }
        if (actionChanged && adjustedAutonomousAction != null) {
            reasons.add("Calibration action bias set autonomous action to " + adjustedAutonomousAction.name() + ".");
        }
        reasons.addAll(limit(profile.evidenceFacts(), 3));
        reasons.addAll(limit(profile.policyFacts(), 2));
        return List.copyOf(reasons);
    }

    private String buildSummary(
            CalibrationProfileRuntimePack.RuntimeCalibrationItem profile,
            String scenarioClass,
            boolean calibrationApplied,
            boolean localConstraintLocked,
            double appliedConfidenceAdjustment,
            boolean actionChanged) {
        if (localConstraintLocked) {
            return String.format(Locale.ROOT,
                    "Calibration profile %s matched scenario %s but local autonomy constraints preserved the final runtime decision.",
                    profile.profileKey(),
                    scenarioClass);
        }
        if (calibrationApplied) {
            return String.format(Locale.ROOT,
                    "Calibration profile %s matched scenario %s and applied post-decision adjustments (confidenceDelta=%.3f, actionBias=%s, actionChanged=%s).",
                    profile.profileKey(),
                    scenarioClass,
                    appliedConfidenceAdjustment,
                    profile.recommendedActionBias(),
                    actionChanged);
        }
        return String.format(Locale.ROOT,
                "Calibration profile %s matched scenario %s but produced no post-decision runtime adjustment.",
                profile.profileKey(),
                scenarioClass);
    }

    private List<String> limit(List<String> facts, int limit) {
        if (facts == null || facts.isEmpty()) {
            return List.of();
        }
        return facts.stream().filter(text -> text != null && !text.isBlank()).limit(limit).toList();
    }

    private ZeroTrustAction applyActionBias(
            ZeroTrustAction enforcedAction,
            ZeroTrustAction proposedAction,
            String actionBias) {
        ZeroTrustAction safeEnforced = enforcedAction != null ? enforcedAction : ZeroTrustAction.ESCALATE;
        if (safeEnforced == ZeroTrustAction.BLOCK) {
            return safeEnforced;
        }
        String normalizedBias = actionBias == null ? "NONE" : actionBias.trim().toUpperCase(Locale.ROOT);
        if ("INCREASE_CHALLENGE".equals(normalizedBias) && safeEnforced == ZeroTrustAction.ALLOW) {
            return ZeroTrustAction.CHALLENGE;
        }
        if ("DECREASE_CHALLENGE".equals(normalizedBias)
                && safeEnforced == ZeroTrustAction.CHALLENGE
                && proposedAction != ZeroTrustAction.BLOCK) {
            return ZeroTrustAction.ALLOW;
        }
        return safeEnforced;
    }

    private double clamp(double value, double min, double max) {
        return Math.max(min, Math.min(max, value));
    }
}