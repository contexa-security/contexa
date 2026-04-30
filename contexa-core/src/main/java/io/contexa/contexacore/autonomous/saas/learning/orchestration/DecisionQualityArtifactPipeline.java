package io.contexa.contexacore.autonomous.saas.learning.orchestration;

import io.contexa.contexacore.autonomous.saas.dto.DecisionQualityProfileSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactGuardrail;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityLearningInput;
import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityLearningPortfolio;
import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityScenarioResult;
import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityLearningService;
import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityProfileSnapshotAssembler;
import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityProfileCandidate;
import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityQualificationDecision;
import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityQualificationPolicy;
import io.contexa.contexacore.autonomous.saas.learning.sanitization.LearningArtifactSanitizationService;
import io.contexa.contexacore.autonomous.saas.learning.transfer.ArtifactTransferEligibilityInput;
import io.contexa.contexacore.autonomous.saas.learning.transfer.ArtifactTransferRiskAssessment;
import io.contexa.contexacore.autonomous.saas.learning.transfer.CrossTenantTransferEligibilityService;

import java.util.List;
import java.util.Locale;

/**
 * End-to-end pipeline that turns scenario-level decision-quality learning into governance telemetry.
 */
public class DecisionQualityArtifactPipeline {

    private final DecisionQualityLearningService learningService;
    private final DecisionQualityQualificationPolicy qualificationPolicy;
    private final DecisionQualityProfileSnapshotAssembler packAssembler;
    private final LearningArtifactSanitizationService sanitizationService;
    private final CrossTenantTransferEligibilityService transferEligibilityService;

    public DecisionQualityArtifactPipeline(
            DecisionQualityLearningService learningService,
            DecisionQualityQualificationPolicy qualificationPolicy,
            DecisionQualityProfileSnapshotAssembler packAssembler,
            LearningArtifactSanitizationService sanitizationService,
            CrossTenantTransferEligibilityService transferEligibilityService) {
        this.learningService = learningService;
        this.qualificationPolicy = qualificationPolicy;
        this.packAssembler = packAssembler;
        this.sanitizationService = sanitizationService;
        this.transferEligibilityService = transferEligibilityService;
    }

    public DecisionQualityArtifactPipelineResult execute(String tenantId, DecisionQualityLearningInput input) {
        DecisionQualityLearningPortfolio portfolio = learningService.evaluate(input);
        List<DecisionQualityProfileCandidate> candidates = portfolio.scenarios().stream()
                .map(sanitizationService::sanitize)
                .map(this::toCandidate)
                .toList();
        ArtifactTransferRiskAssessment transferRisk = transferEligibilityService.assess(toTransferInput(tenantId, portfolio));
        boolean featureEnabled = !portfolio.scenarios().isEmpty();
        DecisionQualityProfileSnapshot snapshot = packAssembler.assembleSnapshot(
                tenantId,
                featureEnabled,
                transferRisk.sharingEnabled(),
                candidates);
        return new DecisionQualityArtifactPipelineResult(portfolio, candidates, transferRisk, snapshot);
    }

    private DecisionQualityProfileCandidate toCandidate(DecisionQualityScenarioResult result) {
        DecisionQualityQualificationDecision decision = qualificationPolicy.evaluate(result);
        return new DecisionQualityProfileCandidate(
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
            DecisionQualityLearningPortfolio portfolio) {
        long candidateCount = portfolio.scenarios().size();
        long sampleSize = portfolio.scenarios().stream().mapToLong(item -> item.biasAggregation().sampleSize()).sum();
        double outcomeCoverage = average(portfolio.scenarios().stream().mapToDouble(item -> ratio(item.biasAggregation().operatorReviewedOutcomeCount(), item.biasAggregation().sampleSize())).toArray());
        double hardNegativeCoverage = average(portfolio.scenarios().stream().mapToDouble(item -> ratio(item.biasAggregation().falsePositiveCount(), item.biasAggregation().sampleSize())).toArray());
        double localLiftRate = average(portfolio.scenarios().stream().mapToDouble(item -> Math.max(0.0d, 1.0d - item.biasAggregation().falseNegativeRate())).toArray());
        return ArtifactTransferEligibilityInput.permissive(
                tenantId,
                LearningArtifactTypeNames.DECISION_QUALITY_PROFILE,
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
            return "DECISION_QUALITY_SAMPLE_FLOOR";
        }
        if (value.contains("REVIEWED OUTCOMES")) {
            return "DECISION_QUALITY_REVIEWED_OUTCOME_FLOOR";
        }
        if (value.contains("FALSE-POSITIVE RATE")) {
            return "DECISION_QUALITY_FALSE_POSITIVE_FLOOR";
        }
        if (value.contains("FALSE-NEGATIVE RATE")) {
            return "DECISION_QUALITY_FALSE_NEGATIVE_FLOOR";
        }
        return "DECISION_QUALITY_EVIDENCE_GATE";
    }
}
