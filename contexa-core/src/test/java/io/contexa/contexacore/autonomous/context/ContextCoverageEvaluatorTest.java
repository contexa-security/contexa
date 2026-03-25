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
                .build();

        ContextCoverageReport report = new ContextCoverageEvaluator().evaluate(context);

        assertThat(report.availableFacts()).contains(
                "Bridge coverage metadata is available.",
                "Bridge authentication source is available.",
                "Bridge authorization source is available.",
                "Bridge delegation source is available.");
        assertThat(report.missingCriticalFacts()).contains("Bridge missing context: DELEGATION.");
        assertThat(report.remediationHints()).contains("Attach peer cohort deltas through enterprise cohort enrichment when available.");
        assertThat(report.confidenceWarnings()).contains("Peer cohort delta is missing; cohort-based deviation claims should remain conservative.");
        assertThat(report.summary()).contains("Bridge coverage: AUTHORIZATION_CONTEXT.");
    }
}
