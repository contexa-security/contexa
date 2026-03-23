package io.contexa.contexacore.autonomous.context;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CanonicalContextFieldPolicyTest {

    @Test
    void determineCoverageLevelShouldRespectCanonicalFieldPolicy() {
        CanonicalSecurityContext scopeAware = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST"))
                        .build())
                .build();

        CanonicalSecurityContext businessAware = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST"))
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .businessLabel("Customer Export Report")
                        .sensitivity("HIGH")
                        .build())
                .build();

        assertThat(CanonicalContextFieldPolicy.determineCoverageLevel(scopeAware))
                .isEqualTo(ContextCoverageLevel.SCOPE_AWARE);
        assertThat(CanonicalContextFieldPolicy.determineCoverageLevel(businessAware))
                .isEqualTo(ContextCoverageLevel.BUSINESS_AWARE);
    }
}
