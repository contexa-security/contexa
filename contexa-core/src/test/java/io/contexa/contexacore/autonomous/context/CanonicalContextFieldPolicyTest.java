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
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                        .sessionAgeMinutes(12)
                        .previousPath("/api/customer/list")
                        .build())
                .build();

        assertThat(CanonicalContextFieldPolicy.determineCoverageLevel(scopeAware))
                .isEqualTo(ContextCoverageLevel.SCOPE_AWARE);
        assertThat(CanonicalContextFieldPolicy.determineCoverageLevel(businessAware))
                .isEqualTo(ContextCoverageLevel.BUSINESS_AWARE);
    }

    @Test
    void workProfileEvidenceShouldBeDistinguishedFromTrustedWorkProfile() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
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

        assertThat(CanonicalContextFieldPolicy.hasWorkProfileEvidence(context)).isTrue();
        assertThat(CanonicalContextFieldPolicy.hasWorkProfile(context)).isFalse();
        assertThat(CanonicalContextFieldPolicy.hasProvisionalWorkProfile(context)).isTrue();
    }
}
