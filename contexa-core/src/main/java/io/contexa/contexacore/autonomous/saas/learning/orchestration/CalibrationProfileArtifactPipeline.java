package io.contexa.contexacore.autonomous.saas.learning.orchestration;

import io.contexa.contexacore.autonomous.saas.dto.CalibrationProfilePackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactGuardrail;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileLearningInput;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileLearningPortfolio;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileLearningScenarioResult;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileLearningService;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfilePackAssembler;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfilePackCandidate;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileQualificationDecision;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileQualificationPolicy;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileRuntimePack;
import io.contexa.contexacore.autonomous.saas.learning.sanitization.LearningArtifactSanitizationService;
import io.contexa.contexacore.autonomous.saas.learning.transfer.ArtifactTransferEligibilityInput;
import io.contexa.contexacore.autonomous.saas.learning.transfer.ArtifactTransferRiskAssessment;
import io.contexa.contexacore.autonomous.saas.learning.transfer.CrossTenantTransferEligibilityService;

import java.util.List;
import java.util.Locale;

/**
 * End-to-end pipeline that turns scenario-level calibration learning into transport and runtime artifacts.
 */
public class CalibrationProfileArtifactPipeline {

    private final CalibrationProfileLearningService learningService;
    private final CalibrationProfileQualificationPolicy qualificationPolicy;
    private final CalibrationProfilePackAssembler packAssembler;
    private final LearningArtifactSanitizationService sanitizationService;
    private final CrossTenantTransferEligibilityService transferEligibilityService;

    public CalibrationProfileArtifactPipeline(
            CalibrationProfileLearningService learningService,
            CalibrationProfileQualificationPolicy qualificationPolicy,
            CalibrationProfilePackAssembler packAssembler,
            LearningArtifactSanitizationService sanitizationService,
            CrossTenantTransferEligibilityService transferEligibilityService) {
        this.learningService = learningService;
        this.qualificationPolicy = qualificationPolicy;
        this.packAssembler = packAssembler;
        this.sanitizationService = sanitizationService;
        this.transferEligibilityService = transferEligibilityService;
    }

    public CalibrationProfileArtifactPipelineResult execute(String tenantId, CalibrationProfileLearningInput input) {
        CalibrationProfileLearningPortfolio portfolio = learningService.evaluate(input);
        List<CalibrationProfilePackCandidate> candidates = portfolio.scenarios().stream()
                .map(sanitizationService::sanitize)
                .map(this::toCandidate)
                .toList();
        ArtifactTransferRiskAssessment transferRisk = transferEligibilityService.assess(toTransferInput(tenantId, portfolio));
        boolean featureEnabled = !portfolio.scenarios().isEmpty();
        CalibrationProfilePackSnapshot snapshot = packAssembler.assembleSnapshot(
                tenantId,
                featureEnabled,
                transferRisk.sharingEnabled(),
                candidates);
        CalibrationProfileRuntimePack runtimePack = transferRisk.sharingEnabled()
                ? packAssembler.assembleRuntimePack(tenantId, candidates)
                : CalibrationProfileRuntimePack.empty();
        return new CalibrationProfileArtifactPipelineResult(portfolio, candidates, transferRisk, snapshot, runtimePack);
    }

    private CalibrationProfilePackCandidate toCandidate(CalibrationProfileLearningScenarioResult result) {
        CalibrationProfileQualificationDecision decision = qualificationPolicy.evaluate(result);
        return new CalibrationProfilePackCandidate(
                result,
                new LearningArtifactMetadata(
                        decision.recommendedReleaseState(),
                        io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics.empty(),
                        decision.blockingReasons().stream()
                                .map(reason -> new LearningArtifactGuardrail(toGuardrailCode(reason), reason, true))
                                .toList()),
                decision.policyFacts());
    }

    private ArtifactTransferEligibilityInput toTransferInput(
            String tenantId,
            CalibrationProfileLearningPortfolio portfolio) {
        long candidateCount = portfolio.scenarios().size();
        long sampleSize = portfolio.scenarios().stream().mapToLong(item -> item.biasAggregation().sampleSize()).sum();
        double outcomeCoverage = average(portfolio.scenarios().stream().mapToDouble(item -> ratio(item.biasAggregation().operatorReviewedOutcomeCount(), item.biasAggregation().sampleSize())).toArray());
        double hardNegativeCoverage = average(portfolio.scenarios().stream().mapToDouble(item -> ratio(item.biasAggregation().falsePositiveCount(), item.biasAggregation().sampleSize())).toArray());
        double localLiftRate = average(portfolio.scenarios().stream().mapToDouble(item -> Math.max(0.0d, 1.0d - item.biasAggregation().falseNegativeRate())).toArray());
        return ArtifactTransferEligibilityInput.permissive(
                tenantId,
                "CALIBRATION_PROFILE",
                candidateCount,
                sampleSize,
                outcomeCoverage,
                hardNegativeCoverage,
                localLiftRate);
    }

    private double average(double[] values) {
        if (values == null || values.length == 0) {
            return 0.0d;
        }
        double sum = 0.0d;
        for (double value : values) {
            sum += value;
        }
        return sum / values.length;
    }

    private double ratio(long numerator, long denominator) {
        if (denominator <= 0L) {
            return 0.0d;
        }
        return (double) numerator / (double) denominator;
    }

    private String toGuardrailCode(String reason) {
        String value = reason == null ? "UNKNOWN" : reason.toUpperCase(Locale.ROOT);
        if (value.contains("SAMPLE SIZE")) {
            return "CALIBRATION_SAMPLE_FLOOR";
        }
        if (value.contains("REVIEWED OUTCOMES")) {
            return "CALIBRATION_REVIEWED_OUTCOME_FLOOR";
        }
        if (value.contains("FALSE-POSITIVE RATE")) {
            return "CALIBRATION_FALSE_POSITIVE_FLOOR";
        }
        if (value.contains("FALSE-NEGATIVE RATE")) {
            return "CALIBRATION_FALSE_NEGATIVE_FLOOR";
        }
        return "CALIBRATION_EVIDENCE_GATE";
    }
}