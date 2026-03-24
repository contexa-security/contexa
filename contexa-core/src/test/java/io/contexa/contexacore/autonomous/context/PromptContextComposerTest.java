package io.contexa.contexacore.autonomous.context;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PromptContextComposerTest {

    @Test
    void composeShouldRenderCoverageIdentityResourceAndDelegationSections() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .organizationId("tenant-acme")
                        .department("finance")
                        .roleSet(List.of("ANALYST"))
                        .authoritySet(List.of("report.read"))
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(true)
                        .recentRequestCount(5)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .businessLabel("Customer Export Report")
                        .sensitivity("HIGH")
                        .actionFamily("READ")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST"))
                        .effectivePermissions(List.of("report.read"))
                        .scopeTags(List.of("customer_data"))
                        .build())
                .observedScope(CanonicalSecurityContext.ObservedScope.builder()
                        .profileSource("PROTECTABLE_ACCESS_HISTORY")
                        .summary("Current resource is rare compared with observed work history.")
                        .recentProtectableAccessCount(12)
                        .recentDeniedAccessCount(1)
                        .frequentResources(List.of("/api/customer/list", "/api/customer/search"))
                        .frequentActionFamilies(List.of("READ", "EXPORT"))
                        .rareCurrentResource(true)
                        .build())
                .delegation(CanonicalSecurityContext.Delegation.builder()
                        .agentId("agent-1")
                        .objectiveFamily("THREAT_KNOWLEDGE_RUNTIME_REUSE")
                        .allowedOperations(List.of("READ"))
                        .containmentOnly(true)
                        .build())
                .bridge(CanonicalSecurityContext.Bridge.builder()
                        .coverageLevel("AUTHORIZATION_CONTEXT")
                        .coverageScore(80)
                        .summary("Bridge resolved authentication and authorization context for the current request.")
                        .remediationHints(List.of("If delegated agents are used, propagate delegation metadata for the current request. Otherwise this gap can be ignored."))
                        .authenticationSource("SECURITY_CONTEXT")
                        .authorizationSource("HEADER")
                        .delegationSource("REQUEST_ATTRIBUTE")
                        .missingContexts(List.of("ORGANIZATION_CONTEXT"))
                        .build())
                .coverage(new ContextCoverageReport(
                        ContextCoverageLevel.BUSINESS_AWARE,
                        List.of("Actor identity is available."),
                        List.of(),
                        "Business-aware context is available for role, resource, and session reasoning."))
                .build();

        String promptSection = new PromptContextComposer().compose(context);

        assertThat(promptSection).contains("=== CONTEXT COVERAGE ===");
        assertThat(promptSection).contains("=== BRIDGE RESOLUTION CONTEXT ===");
        assertThat(promptSection).contains("=== IDENTITY AND ROLE CONTEXT ===");
        assertThat(promptSection).contains("=== RESOURCE AND ACTION CONTEXT ===");
        assertThat(promptSection).contains("=== OBSERVED WORK PATTERN CONTEXT ===");
        assertThat(promptSection).contains("=== DELEGATED OBJECTIVE CONTEXT ===");
        assertThat(promptSection).contains("BridgeAuthenticationSource: SECURITY_CONTEXT");
        assertThat(promptSection).contains("BridgeAuthorizationSource: HEADER");
        assertThat(promptSection).contains("BridgeCoverageSummary: Bridge resolved authentication and authorization context for the current request.");
        assertThat(promptSection).contains("BridgeRemediationHints: If delegated agents are used, propagate delegation metadata for the current request. Otherwise this gap can be ignored.");
        assertThat(promptSection).contains("Customer Export Report");
        assertThat(promptSection).contains("CoverageLevel: BUSINESS_AWARE");
    }
}
