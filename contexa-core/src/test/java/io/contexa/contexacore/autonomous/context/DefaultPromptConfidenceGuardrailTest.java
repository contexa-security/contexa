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
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(true)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/list")
                        .sensitivity("LOW")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ROLE_ANALYST"))
                        .scopeTags(List.of("customer_data"))
                        .build())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                        .summary("Observed list then export flow")
                        .build())
                .workProfile(CanonicalSecurityContext.WorkProfile.builder()
                        .summary("Observed protectable resources /api/customer/list")
                        .frequentProtectableResources(List.of("/api/customer/list"))
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .summary("Expected resource families REPORT")
                        .expectedResourceFamilies(List.of("REPORT"))
                        .expectedActionFamilies(List.of("READ"))
                        .build())
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
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(true)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/list")
                        .sensitivity("LOW")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ROLE_ANALYST"))
                        .scopeTags(List.of("customer_data"))
                        .build())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                        .summary("Observed list then export flow")
                        .build())
                .workProfile(CanonicalSecurityContext.WorkProfile.builder()
                        .summary("Observed protectable resources /api/customer/list")
                        .frequentProtectableResources(List.of("/api/customer/list"))
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .summary("Expected resource families REPORT")
                        .expectedResourceFamilies(List.of("REPORT"))
                        .expectedActionFamilies(List.of("READ"))
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
        assertThat(adjustment.summary()).contains("objective alignment evidence is still incomplete");
    }

    @Test
    void evaluateShouldDowngradeAllowWhenCriticalDecisionContextIsMissing() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .coverage(new ContextCoverageReport(
                        ContextCoverageLevel.BUSINESS_AWARE,
                        List.of("Actor identity is available."),
                        List.of("Effective roles are unavailable.", "Authorization scope is unavailable.", "Resource sensitivity is unavailable."),
                        List.of(),
                        List.of(),
                        "Business-aware context is available."))
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(null)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of())
                        .scopeTags(List.of())
                        .build())
                .build();

        PromptDecisionAdjustment adjustment = guardrail.evaluate(
                context,
                new ProposedPromptDecision(ZeroTrustAction.ALLOW, 0.18, 0.60, "Looks normal.", 1)
        );

        assertThat(adjustment.applied()).isTrue();
        assertThat(adjustment.autonomyConstrained()).isTrue();
        assertThat(adjustment.enforcementAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(adjustment.effectiveConfidence()).isEqualTo(DefaultPromptConfidenceGuardrail.LOW_CONFIDENCE_CAP);
        assertThat(adjustment.summary()).contains("Critical decision context is incomplete");
    }
}
