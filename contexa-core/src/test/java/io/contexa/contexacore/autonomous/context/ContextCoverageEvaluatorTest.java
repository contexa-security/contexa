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
                "Context trust profile PERSONAL_WORK_PROFILE is WEAK; treat it as a hint, not proof.",
                "Action family baseline includes fallback-derived signals; do not treat action semantics as proof of user intent.",
                "Scope limitation: Use this profile to understand enacted work patterns after authorization, not to infer business objective by itself.");
        assertThat(report.summary()).contains("Bridge coverage: AUTHORIZATION_CONTEXT.");
    }
}
