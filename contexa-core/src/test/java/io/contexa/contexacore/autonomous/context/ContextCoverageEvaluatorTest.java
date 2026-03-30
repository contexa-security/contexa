package io.contexa.contexacore.autonomous.context;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ContextCoverageEvaluatorTest {

    @Test
    void evaluateShouldIncludeBridgeFactsInCoverageReport() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .roleSet(List.of("ANALYST"))
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(true)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .businessLabel("Customer Export Report")
                        .sensitivity("HIGH")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST"))
                        .scopeTags(List.of("customer_data"))
                        .build())
                .bridge(CanonicalSecurityContext.Bridge.builder()
                        .coverageLevel("AUTHORIZATION_CONTEXT")
                        .authenticationSource("SECURITY_CONTEXT")
                        .authorizationSource("HEADER")
                        .delegationSource("REQUEST_ATTRIBUTE")
                        .missingContexts(List.of("DELEGATION"))
                        .build())
                .contextTrustProfiles(List.of(ContextTrustProfile.builder()
                        .profileKey("PERSONAL_WORK_PROFILE")
                        .provenanceSummary("collector=PROTECTABLE_WORK_PROFILE_COLLECTOR,window=7d,observations=3,daysCovered=1")
                        .overallQualityGrade(ContextQualityGrade.WEAK)
                        .qualityWarnings(List.of("Action family baseline includes fallback-derived signals; do not treat action semantics as proof of user intent."))
                        .scopeLimitations(List.of("Use this profile to understand enacted work patterns after authorization, not to infer business objective by itself."))
                        .build()))
                .build();

        ContextCoverageReport report = new ContextCoverageEvaluator().evaluate(context);

        assertThat(report.availableFacts()).contains(
                "Bridge coverage metadata is available.",
                "Bridge authentication source is available.",
                "Bridge authorization source is available.",
                "Bridge delegation source is available.",
                "Context trust profile is available for PERSONAL_WORK_PROFILE.",
                "Context provenance summary: collector=PROTECTABLE_WORK_PROFILE_COLLECTOR,window=7d,observations=3,daysCovered=1");
        assertThat(report.missingCriticalFacts()).contains("Bridge missing context: DELEGATION.");
        assertThat(report.remediationHints()).contains("Attach peer cohort deltas through enterprise cohort enrichment when available.");
        assertThat(report.confidenceWarnings()).contains(
                "Peer cohort delta is missing; cohort-based deviation claims should remain conservative.",
                "Context evidence for PERSONAL_WORK_PROFILE is thin, fallback-heavy, or comparison-incomplete; do not use it as a standalone reasoning anchor.",
                "Action family baseline includes fallback-derived signals; do not treat action semantics as proof of user intent.",
                "Scope limitation: Use this profile to understand enacted work patterns after authorization, not to infer business objective by itself.");
        assertThat(report.summary()).contains("Bridge coverage: AUTHORIZATION_CONTEXT.");
    }

    @Test
    void evaluateShouldTreatThinWorkProfileAsProvisionalInsteadOfUnavailable() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(true)
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST"))
                        .scopeTags(List.of("customer_data"))
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .sensitivity("HIGH")
                        .build())
                .workProfile(CanonicalSecurityContext.WorkProfile.builder()
                        .summary("Observed protectable resources /api/customer/list")
                        .frequentProtectableResources(List.of("/api/customer/list"))
                        .build())
                .contextTrustProfiles(List.of(ContextTrustProfile.builder()
                        .profileKey("PERSONAL_WORK_PROFILE")
                        .overallQualityGrade(ContextQualityGrade.WEAK)
                        .overallQualityScore(42)
                        .qualityWarnings(List.of("Work profile baseline is thin; treat pattern claims as provisional until more allowed observations accumulate."))
                        .build()))
                .build();

        ContextCoverageReport report = new ContextCoverageEvaluator().evaluate(context);

        assertThat(report.availableFacts()).contains("Personal work profile evidence is available but provisional.");
        assertThat(report.missingCriticalFacts()).doesNotContain("Personal work profile is unavailable.");
        assertThat(report.confidenceWarnings())
                .anyMatch(value -> value.contains("Personal work profile exists but remains thin"));
    }

    @Test
    void evaluateShouldDescribeRoleScopeAsComparisonEvidenceWhenExplicitAuthorizationFactsAreMissing() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(true)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .sensitivity("HIGH")
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .summary("Current action family READ under observed protectable scope.")
                        .currentActionFamily("READ")
                        .build())
                .build();

        ContextCoverageReport report = new ContextCoverageEvaluator().evaluate(context);

        assertThat(report.availableFacts())
                .contains("Role scope comparison evidence is available, but explicit authorization facts are still partial.");
        assertThat(report.confidenceWarnings())
                .anyMatch(value -> value.contains("explicit authorization facts"));
    }
}
