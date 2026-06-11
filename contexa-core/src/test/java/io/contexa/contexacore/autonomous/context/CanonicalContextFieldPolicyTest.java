/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.context.policy.CanonicalContextFieldPolicy;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageLevel;
import io.contexa.contexacore.autonomous.context.model.ContextQualityGrade;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;

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
