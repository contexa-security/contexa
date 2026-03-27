package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultPromptConfidenceGuardrailTest {

    private final DefaultPromptConfidenceGuardrail guardrail = new DefaultPromptConfidenceGuardrail();

    @Test
    void evaluateShouldCapHighConfidenceAllowWhenCoverageIsEnvironmentOnly() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .coverage(new ContextCoverageReport(
                        ContextCoverageLevel.ENVIRONMENT_ONLY,
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        "Only environment context is available."))
                .build();

        PromptDecisionAdjustment adjustment = guardrail.evaluate(
                context,
                new ProposedPromptDecision(ZeroTrustAction.ALLOW, 0.11, 0.94, "Looks normal.", 1)
        );

        assertThat(adjustment.applied()).isTrue();
        assertThat(adjustment.autonomyConstrained()).isFalse();
        assertThat(adjustment.enforcementAction()).isNull();
        assertThat(adjustment.effectiveConfidence()).isEqualTo(DefaultPromptConfidenceGuardrail.MODERATE_CONFIDENCE_CAP);
        assertThat(adjustment.summary()).contains("environment-only");
    }

    @Test
    void evaluateShouldDowngradePermissiveDecisionWhenSensitiveApprovalStateIsUnknown() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .coverage(new ContextCoverageReport(
                        ContextCoverageLevel.BUSINESS_AWARE,
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        "Business-aware context is available."))
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .sensitiveResource(true)
                        .sensitivity("HIGH")
                        .exportSensitive(true)
                        .build())
                .frictionProfile(CanonicalSecurityContext.FrictionProfile.builder()
                        .approvalRequired(true)
                        .approvalGranted(null)
                        .approvalMissing(true)
                        .approvalStatus("PENDING")
                        .build())
                .build();

        PromptDecisionAdjustment adjustment = guardrail.evaluate(
                context,
                new ProposedPromptDecision(ZeroTrustAction.ALLOW, 0.28, 0.91, "No obvious abuse.", 1)
        );

        assertThat(adjustment.applied()).isTrue();
        assertThat(adjustment.autonomyConstrained()).isTrue();
        assertThat(adjustment.enforcementAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(adjustment.effectiveConfidence()).isEqualTo(DefaultPromptConfidenceGuardrail.LOW_CONFIDENCE_CAP);
        assertThat(adjustment.summary()).contains("Approval is required");
    }

    @Test
    void evaluateShouldCapHighConfidenceBlockWhenBehavioralContextIsMissing() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .coverage(new ContextCoverageReport(
                        ContextCoverageLevel.IDENTITY_AWARE,
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        "Identity-aware context is available."))
                .build();

        PromptDecisionAdjustment adjustment = guardrail.evaluate(
                context,
                new ProposedPromptDecision(ZeroTrustAction.BLOCK, 0.82, 0.96, "Suspicious export.", 1)
        );

        assertThat(adjustment.applied()).isTrue();
        assertThat(adjustment.autonomyConstrained()).isFalse();
        assertThat(adjustment.enforcementAction()).isNull();
        assertThat(adjustment.effectiveConfidence()).isEqualTo(DefaultPromptConfidenceGuardrail.LOW_CONFIDENCE_CAP);
        assertThat(adjustment.summary()).contains("Session narrative, personal work profile, and role scope are missing");
    }

    @Test
    void evaluateShouldCapHighConfidenceAllowWhenDelegatedObjectiveDriftIsUnknown() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .coverage(new ContextCoverageReport(
                        ContextCoverageLevel.BUSINESS_AWARE,
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        "Business-aware context is available."))
                .delegation(CanonicalSecurityContext.Delegation.builder()
                        .delegated(true)
                        .agentId("agent-01")
                        .objectiveId("obj-01")
                        .objectiveFamily("CUSTOMER_SUPPORT")
                        .objectiveDrift(null)
                        .build())
                .build();

        PromptDecisionAdjustment adjustment = guardrail.evaluate(
                context,
                new ProposedPromptDecision(ZeroTrustAction.ALLOW, 0.14, 0.89, "Delegated request appears normal.", 1)
        );

        assertThat(adjustment.applied()).isTrue();
        assertThat(adjustment.autonomyConstrained()).isFalse();
        assertThat(adjustment.enforcementAction()).isNull();
        assertThat(adjustment.effectiveConfidence()).isEqualTo(DefaultPromptConfidenceGuardrail.MODERATE_CONFIDENCE_CAP);
        assertThat(adjustment.summary()).contains("objective drift is still unknown");
    }
}
