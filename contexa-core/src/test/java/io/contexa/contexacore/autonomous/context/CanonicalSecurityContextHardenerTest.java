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

import io.contexa.contexacore.autonomous.context.hardener.CanonicalSecurityContextHardener;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CanonicalSecurityContextHardenerTest {

    @Test
    void hardenShouldStateTheSystemAndTheNetworkInOneForm() {
        // W2-4: a host provider may set them after the context is resolved; the hardener gives them one form.
        CanonicalSecurityContext hardened = new CanonicalSecurityContextHardener().harden(CanonicalSecurityContext.builder()
                .device(CanonicalSecurityContext.Device.builder().os(" Mac OS X ").build())
                .location(CanonicalSecurityContext.Location.builder().ipBand(" 10.40.12 ").networkZone(" office ").build())
                .build());

        assertThat(hardened.getDevice().getOs()).isEqualTo("MAC");
        assertThat(hardened.getLocation().getIpBand()).isEqualTo("10.40.12.0/24");
        assertThat(hardened.getLocation().getNetworkZone()).isEqualTo("CORPORATE");
    }

    @Test
    void hardenShouldTrimNormalizeAndDeduplicateCanonicalFields() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId(" alice ")
                        .organizationId(" ")
                        .principalType(" employee ")
                        .roleSet(List.of("ANALYST", " ANALYST ", ""))
                        .authoritySet(List.of("report.read", " report.read "))
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .currentAccessHour(29)
                        .concurrentSessions(-2)
                        .passwordAgeDays(-9)
                        .build())
                .device(CanonicalSecurityContext.Device.builder()
                        .os(" windows ")
                        .osVersion(" 11 ")
                        .browser(" Chrome ")
                        .browserVersion(" 136 ")
                        .screenResolution(" 1920x1080 ")
                        .language(" ko-KR ")
                        .build())
                .location(CanonicalSecurityContext.Location.builder()
                        .country(" kr ")
                        .city(" Seoul ")
                        .ipBand(" 203.0.113.0/24 ")
                        .asn(" as64512 ")
                        .build())
                .intent(CanonicalSecurityContext.Intent.builder()
                        .missingReferer(true)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceType(" report ")
                        .sensitivity(" high ")
                        .actionFamily(" export ")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST", ""))
                        .scopeTags(List.of("customer_data", " customer_data "))
                        .build())
                .observedScope(CanonicalSecurityContext.ObservedScope.builder()
                        .profileSource(" protectable_access_history ")
                        .recentDeniedAccessCount(-1)
                        .frequentResources(List.of("/a", " /a ", ""))
                        .build())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                        .summary("Session age 0m | previous path /admin/api/security-test/sensitive/resource-001")
                        .sessionAgeMinutes(600)
                        .build())
                .build();

        CanonicalSecurityContext hardened = new CanonicalSecurityContextHardener().harden(context);

        assertThat(hardened.getActor().getUserId()).isEqualTo("alice");
        assertThat(hardened.getActor().getOrganizationId()).isNull();
        assertThat(hardened.getActor().getPrincipalType()).isEqualTo("EMPLOYEE");
        assertThat(hardened.getActor().getRoleSet()).containsExactly("ANALYST");
        assertThat(hardened.getActor().getAuthoritySet()).containsExactly("report.read");
        assertThat(hardened.getSession().getCurrentAccessHour()).isEqualTo(23);
        assertThat(hardened.getSession().getConcurrentSessions()).isZero();
        assertThat(hardened.getSession().getPasswordAgeDays()).isZero();
        assertThat(hardened.getDevice().getOs()).isEqualTo("WINDOWS");
        assertThat(hardened.getDevice().getOsVersion()).isEqualTo("11");
        assertThat(hardened.getDevice().getBrowser()).isEqualTo("Chrome");
        assertThat(hardened.getDevice().getBrowserVersion()).isEqualTo("136");
        assertThat(hardened.getDevice().getScreenResolution()).isEqualTo("1920x1080");
        assertThat(hardened.getDevice().getLanguage()).isEqualTo("ko-KR");
        assertThat(hardened.getLocation().getCountry()).isEqualTo("KR");
        assertThat(hardened.getLocation().getCity()).isEqualTo("Seoul");
        assertThat(hardened.getLocation().getIpBand()).isEqualTo("203.0.113.0/24");
        assertThat(hardened.getLocation().getAsn()).isEqualTo("AS64512");
        assertThat(hardened.getIntent().getMissingReferer()).isTrue();
        assertThat(hardened.getResource().getResourceType()).isEqualTo("REPORT");
        assertThat(hardened.getResource().getSensitivity()).isEqualTo("HIGH");
        assertThat(hardened.getResource().getActionFamily()).isEqualTo("EXPORT");
        assertThat(hardened.getAuthorization().getScopeTags()).containsExactly("customer_data");
        assertThat(hardened.getObservedScope().getProfileSource()).isEqualTo("PROTECTABLE_ACCESS_HISTORY");
        assertThat(hardened.getObservedScope().getRecentDeniedAccessCount()).isZero();
        assertThat(hardened.getObservedScope().getFrequentResources()).containsExactly("/a");
        assertThat(hardened.getSessionNarrativeProfile().getSessionAgeMinutes()).isEqualTo(600);
        assertThat(hardened.getSessionNarrativeProfile().getSummary()).contains("Session age 600m");
        assertThat(hardened.getSessionNarrativeProfile().getSummary()).doesNotContain("Session age 0m");
    }

    @Test
    void hardenKeepsTheOrderAndRepeatsOfASessionSequence() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .roleSet(List.of("ANALYST", " ANALYST "))
                        .build())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                        .sessionActionSequence(List.of("EXPORT", " EXPORT ", "", "READ", "EXPORT"))
                        .sessionProtectableSequence(List.of(
                                "/api/projects/GB-500/exports",
                                "/api/projects/GB-500/exports",
                                "/api/projects/GB-500/exports"))
                        .sessionDecisionHistory(List.of(
                                "2026-09-30T03:17:00Z | POST /api/projects/GB-500/exports | EXPORT | ALLOW",
                                "2026-09-30T03:17:00Z | POST /api/projects/GB-500/exports | EXPORT | ALLOW"))
                        .build())
                .build();

        CanonicalSecurityContext hardened = new CanonicalSecurityContextHardener().harden(context);

        // A set drops repeats; a sequence keeps them, so the same export three times stays three entries (A-2, W1-12).
        assertThat(hardened.getActor().getRoleSet()).containsExactly("ANALYST");
        assertThat(hardened.getSessionNarrativeProfile().getSessionActionSequence())
                .containsExactly("EXPORT", "EXPORT", "READ", "EXPORT");
        assertThat(hardened.getSessionNarrativeProfile().getSessionProtectableSequence()).hasSize(3);
        assertThat(hardened.getSessionNarrativeProfile().getSessionDecisionHistory()).hasSize(2);
    }

    @Test
    void hardenShouldPutEveryActionFamilyInOneVocabulary() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder().actionFamily("CREATE").httpMethod("POST").build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .currentActionFamily("create")
                        .expectedActionFamilies(List.of("UPDATE", "DOWNLOAD", "WRITE"))
                        .build())
                .build();

        CanonicalSecurityContext hardened = new CanonicalSecurityContextHardener().harden(context);

        // One request, one family: the resource and the role scope no longer disagree (A-6, W2-1).
        assertThat(hardened.getResource().getActionFamily()).isEqualTo("WRITE");
        assertThat(hardened.getRoleScopeProfile().getCurrentActionFamily()).isEqualTo("WRITE");
        assertThat(hardened.getRoleScopeProfile().getExpectedActionFamilies()).containsExactly("WRITE", "READ");
    }

    @Test
    void hardenStatesTheLookedUpRecordKindsInOneCaseOnce() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .frictionProfile(CanonicalSecurityContext.FrictionProfile.builder()
                        .checkedRecordKinds(new ArrayList<>(List.of(" ticket ", "TICKET", "on_call"))).build())
                .build();

        CanonicalSecurityContext hardened = new CanonicalSecurityContextHardener().harden(context);

        // The engine compares the kinds with its own constants (P2 correction 3).
        assertThat(hardened.getFrictionProfile().getCheckedRecordKinds()).containsExactly("TICKET", "ON_CALL");
    }
}
