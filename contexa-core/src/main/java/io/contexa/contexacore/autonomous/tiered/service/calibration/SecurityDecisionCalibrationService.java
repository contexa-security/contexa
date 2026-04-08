package io.contexa.contexacore.autonomous.tiered.service.calibration;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.SaasCalibrationProfilePackService;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationLearningObservation;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileRuntimePack;
import io.contexa.contexacore.autonomous.saas.learning.calibration.ScenarioClassResolution;
import io.contexa.contexacore.autonomous.saas.learning.calibration.ScenarioClassResolver;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactRuntimeConflictService;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Orchestrates post-decision calibration using promoted runtime profiles only.
 */
public class SecurityDecisionCalibrationService {

    private final SaasCalibrationProfilePackService calibrationProfilePackService;
    private final CalibrationRuntimeObservationFactory observationFactory;
    private final ScenarioClassResolver scenarioClassResolver;
    private final CalibrationProfileSelector calibrationProfileSelector;
    private final CalibrationDecisionApplier calibrationDecisionApplier;
    private final LearningArtifactRuntimeConflictService runtimeConflictService;

    public SecurityDecisionCalibrationService(
            SaasCalibrationProfilePackService calibrationProfilePackService,
            CalibrationRuntimeObservationFactory observationFactory,
            ScenarioClassResolver scenarioClassResolver,
            CalibrationProfileSelector calibrationProfileSelector,
            CalibrationDecisionApplier calibrationDecisionApplier) {
        this(
                calibrationProfilePackService,
                observationFactory,
                scenarioClassResolver,
                calibrationProfileSelector,
                calibrationDecisionApplier,
                null);
    }

    public SecurityDecisionCalibrationService(
            SaasCalibrationProfilePackService calibrationProfilePackService,
            CalibrationRuntimeObservationFactory observationFactory,
            ScenarioClassResolver scenarioClassResolver,
            CalibrationProfileSelector calibrationProfileSelector,
            CalibrationDecisionApplier calibrationDecisionApplier,
            LearningArtifactRuntimeConflictService runtimeConflictService) {
        this.calibrationProfilePackService = Objects.requireNonNull(calibrationProfilePackService, "calibrationProfilePackService is required");
        this.observationFactory = Objects.requireNonNull(observationFactory, "observationFactory is required");
        this.scenarioClassResolver = Objects.requireNonNull(scenarioClassResolver, "scenarioClassResolver is required");
        this.calibrationProfileSelector = Objects.requireNonNull(calibrationProfileSelector, "calibrationProfileSelector is required");
        this.calibrationDecisionApplier = Objects.requireNonNull(calibrationDecisionApplier, "calibrationDecisionApplier is required");
        this.runtimeConflictService = runtimeConflictService;
    }

    public SecurityDecision apply(
            SecurityEvent event,
            SecurityDecision decision,
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis) {
        if (event == null || decision == null || !calibrationProfilePackService.isEnabled()) {
            return decision;
        }
        CalibrationProfileRuntimePack runtimePack = calibrationProfilePackService.getRuntimePack();
        if (runtimePack == null || !runtimePack.runtimeReady() || runtimePack.profiles().isEmpty()) {
            return decision;
        }

        CalibrationLearningObservation observation = observationFactory.create(event, decision, behaviorAnalysis);
        ScenarioClassResolution scenarioResolution = scenarioClassResolver.resolve(observation);
        if (!scenarioResolution.isResolved()) {
            return decision;
        }

        CalibrationProfileRuntimePack.RuntimeCalibrationItem profile =
                calibrationProfileSelector.select(runtimePack, scenarioResolution.scenarioClass());
        if (profile == null) {
            return decision;
        }

        SecurityDecision calibratedDecision = calibrationDecisionApplier.apply(decision, scenarioResolution, profile);
        recordRuntimeConflictIfRequired(runtimePack.tenantId(), scenarioResolution, profile, calibratedDecision);
        return calibratedDecision;
    }

    private void recordRuntimeConflictIfRequired(
            String tenantId,
            ScenarioClassResolution scenarioResolution,
            CalibrationProfileRuntimePack.RuntimeCalibrationItem profile,
            SecurityDecision calibratedDecision) {
        if (runtimeConflictService == null
                || profile == null
                || calibratedDecision == null
                || !Boolean.TRUE.equals(calibratedDecision.getAutonomyConstraintApplied())
                || !profileRequestsRuntimeChange(profile)
                || !StringUtils.hasText(tenantId)
                || !StringUtils.hasText(profile.profileKey())) {
            return;
        }
        runtimeConflictService.recordReviewOnlyConflict(
                tenantId,
                LearningArtifactTypeNames.CALIBRATION_PROFILE,
                profile.profileKey(),
                profile.profileVersion(),
                "Local autonomy constraints overrode the promoted calibration profile at runtime.",
                buildRuntimeConflictFacts(scenarioResolution, profile, calibratedDecision));
    }

    private boolean profileRequestsRuntimeChange(CalibrationProfileRuntimePack.RuntimeCalibrationItem profile) {
        return profile != null
                && (hasNonZeroConfidenceAdjustment(profile.recommendedConfidenceAdjustment())
                || hasActionBias(profile.recommendedActionBias()));
    }

    private boolean hasNonZeroConfidenceAdjustment(double adjustment) {
        return Double.isFinite(adjustment) && Double.compare(adjustment, 0.0d) != 0;
    }

    private boolean hasActionBias(String actionBias) {
        return StringUtils.hasText(actionBias) && !"NONE".equalsIgnoreCase(actionBias.trim());
    }

    private List<String> buildRuntimeConflictFacts(
            ScenarioClassResolution scenarioResolution,
            CalibrationProfileRuntimePack.RuntimeCalibrationItem profile,
            SecurityDecision calibratedDecision) {
        ArrayList<String> facts = new ArrayList<>();
        if (scenarioResolution != null && scenarioResolution.isResolved()) {
            facts.add("scenarioClass=" + scenarioResolution.scenarioClass());
        }
        facts.add("localAutonomyConstraintApplied=true");
        facts.add("calibrationProfileKey=" + profile.profileKey());
        if (StringUtils.hasText(profile.recommendedActionBias())) {
            facts.add("calibrationActionBias=" + profile.recommendedActionBias());
        }
        if (hasNonZeroConfidenceAdjustment(profile.recommendedConfidenceAdjustment())) {
            facts.add(String.format(Locale.ROOT,
                    "calibrationConfidenceAdjustment=%.3f",
                    profile.recommendedConfidenceAdjustment()));
        }
        if (StringUtils.hasText(calibratedDecision.getAutonomyConstraintSummary())) {
            facts.add("autonomyConstraintSummary=" + calibratedDecision.getAutonomyConstraintSummary());
        }
        addLimitedFacts(facts, scenarioResolution != null ? scenarioResolution.resolutionFacts() : List.of(), 3);
        addLimitedFacts(facts, profile.evidenceFacts(), 2);
        addLimitedFacts(facts, profile.policyFacts(), 2);
        return List.copyOf(facts);
    }

    private void addLimitedFacts(List<String> target, List<String> source, int limit) {
        if (source == null || source.isEmpty() || limit <= 0) {
            return;
        }
        source.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .limit(limit)
                .forEach(target::add);
    }
}