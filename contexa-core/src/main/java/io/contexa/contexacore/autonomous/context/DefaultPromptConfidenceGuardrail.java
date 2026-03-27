package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class DefaultPromptConfidenceGuardrail implements PromptConfidenceGuardrail {

    static final double HIGH_CONFIDENCE_THRESHOLD = 0.85d;
    static final double MODERATE_CONFIDENCE_CAP = 0.74d;
    static final double LOW_CONFIDENCE_CAP = 0.54d;

    @Override
    public PromptDecisionAdjustment evaluate(CanonicalSecurityContext context, ProposedPromptDecision decision) {
        if (decision == null) {
            return PromptDecisionAdjustment.noChange(null);
        }

        ZeroTrustAction originalAction = decision.action() != null ? decision.action() : ZeroTrustAction.ESCALATE;
        ZeroTrustAction enforcementAction = null;
        Double originalConfidence = normalizeScore(decision.confidence());
        Double effectiveConfidence = originalConfidence;
        List<String> reasons = new ArrayList<>();

        if (requiresSensitiveApprovalOverride(context, originalAction)) {
            ZeroTrustAction conservativeAction = chooseConservativeAction(context);
            if (conservativeAction != null && conservativeAction != originalAction) {
                enforcementAction = conservativeAction;
                reasons.add("Approval is required but still unknown for a sensitive request; autonomous allow is not permitted.");
            }
            effectiveConfidence = capConfidence(effectiveConfidence, LOW_CONFIDENCE_CAP);
            reasons.add("Sensitive approval state is unresolved; confidence remains limited until approval lineage is explicit.");
        }

        if (isHighConfidenceAllowWithEnvironmentOnlyCoverage(context, originalAction, effectiveConfidence)) {
            effectiveConfidence = capConfidence(effectiveConfidence, MODERATE_CONFIDENCE_CAP);
            reasons.add("Coverage is environment-only; high-confidence ALLOW is not permitted.");
        }

        if (isHighConfidenceExtremeActionWithoutBehavioralContext(context, originalAction, effectiveConfidence)) {
            effectiveConfidence = capConfidence(effectiveConfidence, LOW_CONFIDENCE_CAP);
            reasons.add("Session narrative, personal work profile, and role scope are missing; extreme confidence is not justified.");
        }

        if (isHighConfidenceAllowWithUnknownObjectiveDrift(context, originalAction, effectiveConfidence)) {
            effectiveConfidence = capConfidence(effectiveConfidence, MODERATE_CONFIDENCE_CAP);
            reasons.add("Delegated objective alignment evidence is still incomplete; high-confidence ALLOW is not permitted.");
        }

        if (reasons.isEmpty()) {
            return PromptDecisionAdjustment.noChange(originalConfidence);
        }

        return new PromptDecisionAdjustment(
                true,
                !scoresEqual(originalConfidence, effectiveConfidence),
                enforcementAction != null,
                enforcementAction,
                effectiveConfidence,
                List.copyOf(reasons),
                String.join(" ", reasons)
        );
    }

    private boolean isHighConfidenceAllowWithEnvironmentOnlyCoverage(
            CanonicalSecurityContext context,
            ZeroTrustAction action,
            Double confidence) {
        return action == ZeroTrustAction.ALLOW
                && isHighConfidence(confidence)
                && context != null
                && context.getCoverage() != null
                && context.getCoverage().level() == ContextCoverageLevel.ENVIRONMENT_ONLY;
    }

    private boolean isHighConfidenceExtremeActionWithoutBehavioralContext(
            CanonicalSecurityContext context,
            ZeroTrustAction action,
            Double confidence) {
        if ((action != ZeroTrustAction.ALLOW && action != ZeroTrustAction.BLOCK) || !isHighConfidence(confidence) || context == null) {
            return false;
        }
        return !CanonicalContextFieldPolicy.hasSessionNarrativeProfile(context)
                && !CanonicalContextFieldPolicy.hasWorkProfile(context)
                && !CanonicalContextFieldPolicy.hasRoleScopeProfile(context);
    }

    private boolean isHighConfidenceAllowWithUnknownObjectiveDrift(
            CanonicalSecurityContext context,
            ZeroTrustAction action,
            Double confidence) {
        if (action != ZeroTrustAction.ALLOW || !isHighConfidence(confidence) || context == null) {
            return false;
        }
        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        return delegation != null
                && hasDelegatedObjective(delegation)
                && delegation.getObjectiveDrift() == null;
    }

    private boolean requiresSensitiveApprovalOverride(CanonicalSecurityContext context, ZeroTrustAction action) {
        if (context == null || action != ZeroTrustAction.ALLOW) {
            return false;
        }
        CanonicalSecurityContext.FrictionProfile friction = context.getFrictionProfile();
        if (friction == null || !Boolean.TRUE.equals(friction.getApprovalRequired())) {
            return false;
        }
        return isApprovalUnknown(friction) && isSensitiveResource(context.getResource());
    }

    private ZeroTrustAction chooseConservativeAction(CanonicalSecurityContext context) {
        if (context == null || context.getCoverage() == null) {
            return ZeroTrustAction.ESCALATE;
        }
        return switch (context.getCoverage().level()) {
            case ENVIRONMENT_ONLY, IDENTITY_AWARE -> ZeroTrustAction.ESCALATE;
            case SCOPE_AWARE, BUSINESS_AWARE -> ZeroTrustAction.CHALLENGE;
        };
    }

    private boolean isApprovalUnknown(CanonicalSecurityContext.FrictionProfile friction) {
        if (Boolean.TRUE.equals(friction.getApprovalMissing())) {
            return true;
        }
        if (friction.getApprovalGranted() != null) {
            return false;
        }
        if (!StringUtils.hasText(friction.getApprovalStatus())) {
            return true;
        }
        String normalized = friction.getApprovalStatus().trim().toUpperCase(Locale.ROOT);
        return "UNKNOWN".equals(normalized) || "PENDING".equals(normalized);
    }

    private boolean isSensitiveResource(CanonicalSecurityContext.Resource resource) {
        if (resource == null) {
            return false;
        }
        if (Boolean.TRUE.equals(resource.getSensitiveResource())
                || Boolean.TRUE.equals(resource.getExportSensitive())
                || Boolean.TRUE.equals(resource.getPrivileged())) {
            return true;
        }
        if (!StringUtils.hasText(resource.getSensitivity())) {
            return false;
        }
        String normalized = resource.getSensitivity().trim().toUpperCase(Locale.ROOT);
        return normalized.contains("HIGH")
                || normalized.contains("CRITICAL")
                || normalized.contains("CONFIDENTIAL")
                || normalized.contains("RESTRICTED")
                || normalized.contains("SECRET");
    }

    private boolean hasDelegatedObjective(CanonicalSecurityContext.Delegation delegation) {
        return Boolean.TRUE.equals(delegation.getDelegated())
                || StringUtils.hasText(delegation.getObjectiveId())
                || StringUtils.hasText(delegation.getObjectiveFamily())
                || StringUtils.hasText(delegation.getAgentId());
    }

    private boolean isHighConfidence(Double confidence) {
        return confidence != null && confidence >= HIGH_CONFIDENCE_THRESHOLD;
    }

    private Double capConfidence(Double confidence, double cap) {
        if (confidence == null) {
            return cap;
        }
        return Math.min(confidence, cap);
    }

    private Double normalizeScore(Double value) {
        if (value == null || !Double.isFinite(value)) {
            return null;
        }
        return Math.max(0.0d, Math.min(1.0d, value));
    }

    private boolean scoresEqual(Double left, Double right) {
        if (left == null && right == null) {
            return true;
        }
        if (left == null || right == null) {
            return false;
        }
        return Math.abs(left - right) < 0.000001d;
    }
}
