package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.context.inference.DefaultPromptConfidenceGuardrail;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageLevel;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageReport;
import io.contexa.contexacore.autonomous.context.model.ContextQualityGrade;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;
import io.contexa.contexacore.autonomous.context.model.PromptDecisionAdjustment;
import io.contexa.contexacore.autonomous.context.model.ProposedPromptDecision;

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
        assertThat(adjustment.effectiveConfidence()).isEqualTo(0.74d);
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
        assertThat(adjustment.effectiveConfidence()).isEqualTo(0.54d);
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
        assertThat(adjustment.effectiveConfidence()).isEqualTo(0.54d);
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
        assertThat(adjustment.effectiveConfidence()).isEqualTo(0.74d);
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
        assertThat(adjustment.effectiveConfidence()).isEqualTo(0.54d);
        assertThat(adjustment.summary()).contains("Critical decision context is incomplete");
    }

    @Test
    void evaluateShouldCapSensitiveAllowWhenRoleScopeEvidenceIsProvisional() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .coverage(new ContextCoverageReport(
                        ContextCoverageLevel.BUSINESS_AWARE,
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        "Business-aware context is available."))
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-sensitive")
                        .mfaVerified(true)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .sensitiveResource(true)
                        .sensitivity("HIGH")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ROLE_ANALYST"))
                        .scopeTags(List.of("customer_data"))
                        .build())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                        .summary("Observed follow-up export request inside the same session")
                        .build())
                .workProfile(CanonicalSecurityContext.WorkProfile.builder()
                        .summary("Observed export resource family and customer data workflow")
                        .frequentProtectableResources(List.of("/api/customer/export"))
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .summary("Observed scope evidence is still provisional")
                        .build())
                .contextTrustProfiles(List.of(ContextTrustProfile.builder()
                        .profileKey("ROLE_SCOPE_PROFILE")
                        .summary("Role scope evidence is still provisional")
                        .overallQualityGrade(ContextQualityGrade.WEAK)
                        .build()))
                .build();

        PromptDecisionAdjustment adjustment = guardrail.evaluate(
                context,
                new ProposedPromptDecision(ZeroTrustAction.ALLOW, 0.22, 0.86, "Observed evidence remains provisional.", 1)
        );

        assertThat(adjustment.applied()).isTrue();
        assertThat(adjustment.autonomyConstrained()).isFalse();
        assertThat(adjustment.enforcementAction()).isNull();
        assertThat(adjustment.effectiveConfidence()).isCloseTo(0.70d, within(0.000001d));
        assertThat(adjustment.summary()).contains("ALLOW confidence cannot exceed 0.70");
    }
}
