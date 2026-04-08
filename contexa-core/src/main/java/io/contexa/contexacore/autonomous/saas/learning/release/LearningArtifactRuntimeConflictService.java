package io.contexa.contexacore.autonomous.saas.learning.release;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import io.contexa.contexacore.autonomous.saas.learning.registry.LearningArtifactRegistryEntry;
import io.contexa.contexacore.autonomous.saas.learning.registry.LearningArtifactRegistryService;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
/**
 * Applies runtime conflict downgrade rules when local truth overrides promoted SaaS artifacts.
 */
@Service
public class LearningArtifactRuntimeConflictService {
    private static final String RUNTIME_CONFLICT_GUARD_ACTOR = "RUNTIME_CONFLICT_GUARD";
    private final LearningArtifactReleaseLedgerService ledgerService;
    private final LearningArtifactRegistryService registryService;
    private final LearningArtifactRuntimeConflictThresholds thresholds;
    public LearningArtifactRuntimeConflictService(LearningArtifactReleaseLedgerService ledgerService) {
        this(ledgerService, null, LearningArtifactRuntimeConflictThresholds.defaults());
    }
    public LearningArtifactRuntimeConflictService(
            LearningArtifactReleaseLedgerService ledgerService,
            LearningArtifactRuntimeConflictThresholds thresholds) {
        this(ledgerService, null, thresholds);
    }
    public LearningArtifactRuntimeConflictService(
            LearningArtifactReleaseLedgerService ledgerService,
            LearningArtifactRegistryService registryService,
            LearningArtifactRuntimeConflictThresholds thresholds) {
        this.ledgerService = ledgerService;
        this.registryService = registryService;
        this.thresholds = thresholds == null ? LearningArtifactRuntimeConflictThresholds.defaults() : thresholds;
    }
    public boolean isRuntimeSuppressed(String tenantId, String artifactType, String artifactKey) {
        validateRequired(tenantId, "tenantId");
        validateRequired(artifactType, "artifactType");
        validateRequired(artifactKey, "artifactKey");
        if (registryService != null) {
            return registryService.current(tenantId, artifactType, artifactKey)
                    .map(LearningArtifactRegistryEntry::runtimeSuppressed)
                    .orElse(false);
        }
        return resolveLatestReleaseState(tenantId, artifactType, artifactKey)
                .map(this::isSuppressingState)
                .orElse(false);
    }
    public boolean recordReviewOnlyConflict(
            String tenantId,
            String artifactType,
            String artifactKey,
            String artifactVersion,
            String reason,
            List<String> facts) {
        LearningArtifactRuntimeConflictResolution resolution = resolveAndRecordConflict(
                tenantId,
                artifactType,
                artifactKey,
                artifactVersion,
                new LearningArtifactRuntimeConflictInput(
                        true,
                        LearningArtifactTypeNames.COHORT_SEED.equals(artifactType),
                        false,
                        1.0d,
                        0.0d,
                        0,
                        0,
                        reason,
                        facts));
        return resolution.recorded();
    }
    public LearningArtifactRuntimeConflictResolution resolveAndRecordConflict(
            String tenantId,
            String artifactType,
            String artifactKey,
            String artifactVersion,
            LearningArtifactRuntimeConflictInput input) {
        validateRequired(tenantId, "tenantId");
        validateRequired(artifactType, "artifactType");
        validateRequired(artifactKey, "artifactKey");
        if (input == null) {
            throw new IllegalArgumentException("input is required");
        }
        LearningArtifactRuntimeConflictResolution planned = resolveConflict(artifactType, input);
        if (planned.remediationAction() == LearningArtifactRuntimeRemediationAction.NO_ACTION) {
            return planned;
        }
        LearningArtifactReleaseState currentState = resolveLatestReleaseState(tenantId, artifactType, artifactKey).orElse(null);
        if (isAlreadySuppressedAtOrAbove(currentState, planned.resultingReleaseState())) {
            return new LearningArtifactRuntimeConflictResolution(
                    planned.cause(),
                    planned.remediationAction(),
                    planned.resultingReleaseState(),
                    false,
                    planned.reason(),
                    planned.policyFacts());
        }
        List<String> normalizedFacts = normalizeFacts(input.facts());
        normalizedFacts.add(0, "runtimeConflictCause=" + planned.cause().name());
        normalizedFacts.add(1, "runtimeRemediationAction=" + planned.remediationAction().name());
        switch (planned.remediationAction()) {
            case DOWNGRADE_TO_REVIEW_ONLY -> ledgerService.recordRollback(
                    tenantId,
                    artifactType,
                    artifactKey,
                    artifactVersion,
                    RUNTIME_CONFLICT_GUARD_ACTOR,
                    planned.reason(),
                    LearningArtifactReleaseState.REVIEW_ONLY,
                    LearningArtifactReleaseState.REVIEW_ONLY,
                    normalizedFacts);
            case WITHDRAW_ARTIFACT -> ledgerService.recordWithdrawn(
                    tenantId,
                    artifactType,
                    artifactKey,
                    artifactVersion,
                    RUNTIME_CONFLICT_GUARD_ACTOR,
                    planned.reason(),
                    normalizedFacts);
            case ACTIVATE_KILL_SWITCH -> ledgerService.recordKillSwitchActivated(
                    tenantId,
                    artifactType,
                    artifactKey,
                    artifactVersion,
                    RUNTIME_CONFLICT_GUARD_ACTOR,
                    planned.reason(),
                    normalizedFacts);
            default -> {
                return planned;
            }
        }
        return new LearningArtifactRuntimeConflictResolution(
                planned.cause(),
                planned.remediationAction(),
                planned.resultingReleaseState(),
                true,
                planned.reason(),
                normalizedFacts);
    }
    public LearningArtifactRuntimeConflictResolution resolveConflict(
            String artifactType,
            LearningArtifactRuntimeConflictInput input) {
        validateRequired(artifactType, "artifactType");
        if (input == null) {
            throw new IllegalArgumentException("input is required");
        }
        List<String> policyFacts = new ArrayList<>();
        policyFacts.add(String.format(
                "evidenceCoverageRate=%.4f falsePositiveRegressionRate=%.4f repeatedConflictCount=%d operatorRegressionCount=%d",
                input.evidenceCoverageRate(),
                input.falsePositiveRegressionRate(),
                input.repeatedConflictCount(),
                input.operatorRegressionCount()));
        if (LearningArtifactTypeNames.PROMPT_PRESENTATION.equals(artifactType) && input.promptBiasRiskHigh()) {
            policyFacts.add("Prompt presentation artifact exposed high bias risk at runtime.");
            return resolution(
                    LearningArtifactRuntimeConflictCause.PROMPT_BIAS_RISK,
                    LearningArtifactRuntimeRemediationAction.ACTIVATE_KILL_SWITCH,
                    LearningArtifactReleaseState.KILL_SWITCH_ACTIVE,
                    normalizeReason(input.reason(), "Prompt presentation artifact showed high runtime bias risk and triggered the tenant kill switch."),
                    policyFacts);
        }
        if (input.repeatedConflictCount() >= thresholds.withdrawRepeatedConflictCount()) {
            policyFacts.add("Repeated runtime conflicts exceeded the withdrawal threshold.");
            return resolution(
                    LearningArtifactRuntimeConflictCause.REPEATED_RUNTIME_CONFLICT,
                    LearningArtifactRuntimeRemediationAction.WITHDRAW_ARTIFACT,
                    LearningArtifactReleaseState.WITHDRAWN,
                    normalizeReason(input.reason(), "Learning artifact was withdrawn after repeated runtime conflicts."),
                    policyFacts);
        }
        if (input.falsePositiveRegressionRate() >= thresholds.withdrawFalsePositiveRateThreshold()) {
            policyFacts.add("False-positive regression exceeded the withdrawal threshold.");
            return resolution(
                    LearningArtifactRuntimeConflictCause.HIGH_FALSE_POSITIVE_REGRESSION,
                    LearningArtifactRuntimeRemediationAction.WITHDRAW_ARTIFACT,
                    LearningArtifactReleaseState.WITHDRAWN,
                    normalizeReason(input.reason(), "Learning artifact was withdrawn because false-positive regression exceeded the accepted threshold."),
                    policyFacts);
        }
        if (input.operatorRegressionCount() >= thresholds.withdrawOperatorRegressionCount()) {
            policyFacts.add("Operator-reviewed regression count exceeded the withdrawal threshold.");
            return resolution(
                    LearningArtifactRuntimeConflictCause.OPERATOR_REVIEW_REGRESSION,
                    LearningArtifactRuntimeRemediationAction.WITHDRAW_ARTIFACT,
                    LearningArtifactReleaseState.WITHDRAWN,
                    normalizeReason(input.reason(), "Learning artifact was withdrawn because operator-reviewed regressions accumulated beyond the accepted threshold."),
                    policyFacts);
        }
        if (LearningArtifactTypeNames.COHORT_SEED.equals(artifactType) && input.localBaselineEstablished()) {
            policyFacts.add("Local baselines are established, so cohort influence must remain review-only.");
            return resolution(
                    LearningArtifactRuntimeConflictCause.COHORT_OVERREACH,
                    LearningArtifactRuntimeRemediationAction.DOWNGRADE_TO_REVIEW_ONLY,
                    LearningArtifactReleaseState.REVIEW_ONLY,
                    normalizeReason(input.reason(), "Qualified cohort seed conflicted with mature local baselines and was downgraded to review-only."),
                    policyFacts);
        }
        if (input.evidenceCoverageRate() < thresholds.reviewOnlyEvidenceCoverageFloor()) {
            policyFacts.add("Runtime evidence coverage is below the review-only floor.");
            return resolution(
                    LearningArtifactRuntimeConflictCause.LOW_EVIDENCE_RUNTIME_MISMATCH,
                    LearningArtifactRuntimeRemediationAction.DOWNGRADE_TO_REVIEW_ONLY,
                    LearningArtifactReleaseState.REVIEW_ONLY,
                    normalizeReason(input.reason(), "Learning artifact was downgraded to review-only because runtime evidence coverage was insufficient."),
                    policyFacts);
        }
        if (input.localTruthOverrode()) {
            policyFacts.add("Local truth overrode the SaaS artifact during runtime application.");
            return resolution(
                    LearningArtifactRuntimeConflictCause.LOCAL_TRUTH_OVERRIDE,
                    LearningArtifactRuntimeRemediationAction.DOWNGRADE_TO_REVIEW_ONLY,
                    LearningArtifactReleaseState.REVIEW_ONLY,
                    normalizeReason(input.reason(), "Local truth overrode the promoted SaaS artifact at runtime and downgraded it to review-only."),
                    policyFacts);
        }
        policyFacts.add("No remediation threshold was exceeded.");
        return resolution(
                LearningArtifactRuntimeConflictCause.NONE,
                LearningArtifactRuntimeRemediationAction.NO_ACTION,
                null,
                normalizeReason(input.reason(), "Runtime conflict inputs did not require remediation."),
                policyFacts);
    }
    private LearningArtifactRuntimeConflictResolution resolution(
            LearningArtifactRuntimeConflictCause cause,
            LearningArtifactRuntimeRemediationAction remediationAction,
            LearningArtifactReleaseState resultingReleaseState,
            String reason,
            List<String> policyFacts) {
        return new LearningArtifactRuntimeConflictResolution(
                cause,
                remediationAction,
                resultingReleaseState,
                false,
                reason,
                List.copyOf(policyFacts));
    }
    private Optional<LearningArtifactReleaseState> resolveLatestReleaseState(
            String tenantId,
            String artifactType,
            String artifactKey) {
        if (registryService != null) {
            Optional<LearningArtifactReleaseState> registryState = registryService.current(tenantId.trim(), artifactType.trim(), artifactKey.trim())
                    .map(LearningArtifactRegistryEntry::releaseState);
            if (registryState.isPresent()) {
                return registryState;
            }
        }
        return ledgerService.latest(tenantId.trim(), artifactType.trim(), artifactKey.trim())
                .map(LearningArtifactReleaseLedgerEntry::releaseState);
    }
    private boolean isSuppressingState(LearningArtifactReleaseState releaseState) {
        return releaseState == LearningArtifactReleaseState.REVIEW_ONLY
                || releaseState == LearningArtifactReleaseState.WITHDRAWN
                || releaseState == LearningArtifactReleaseState.KILL_SWITCH_ACTIVE;
    }
    private boolean isAlreadySuppressedAtOrAbove(
            LearningArtifactReleaseState currentState,
            LearningArtifactReleaseState requestedState) {
        if (currentState == null || requestedState == null) {
            return false;
        }
        return suppressionRank(currentState) >= suppressionRank(requestedState);
    }
    private int suppressionRank(LearningArtifactReleaseState state) {
        if (state == LearningArtifactReleaseState.KILL_SWITCH_ACTIVE) {
            return 3;
        }
        if (state == LearningArtifactReleaseState.WITHDRAWN) {
            return 2;
        }
        if (state == LearningArtifactReleaseState.REVIEW_ONLY) {
            return 1;
        }
        return 0;
    }
    private List<String> normalizeFacts(List<String> facts) {
        if (facts == null || facts.isEmpty()) {
            return new ArrayList<>();
        }
        return facts.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .collect(Collectors.toCollection(ArrayList::new));
    }
    private String normalizeReason(String reason) {
        if (StringUtils.hasText(reason)) {
            return reason.trim();
        }
        return "Local truth overrode the promoted SaaS artifact at runtime and downgraded it to review-only.";
    }
    private String normalizeReason(String reason, String fallback) {
        return StringUtils.hasText(reason) ? reason.trim() : fallback;
    }
    private void validateRequired(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
    }
}