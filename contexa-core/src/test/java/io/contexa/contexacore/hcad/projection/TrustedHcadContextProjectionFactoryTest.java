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
package io.contexa.contexacore.hcad.projection;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAssessment;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionScorer;
import io.contexa.contexacore.hcad.store.BaselineDataStore;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TrustedHcadContextProjectionFactoryTest {

    @Mock
    private HCADDataStore hcadDataStore;

    @Mock
    private SecurityContextDataStore securityContextDataStore;

    @Mock
    private BaselineDataStore baselineDataStore;

    private HcadProperties properties;
    private TrustedHcadContextProjectionFactory factory;
    private HcadPreProtectablePromotionScorer scorer;

    @BeforeEach
    void setUp() {
        properties = new HcadProperties();
        factory = new TrustedHcadContextProjectionFactory(hcadDataStore, securityContextDataStore, baselineDataStore, properties);
        scorer = new HcadPreProtectablePromotionScorer(properties);
        when(hcadDataStore.getRecentRequestCount(anyString(), anyLong(), anyLong())).thenReturn(0);
        when(hcadDataStore.getSessionMetadata(anyString())).thenReturn(Map.of());
        when(baselineDataStore.getUserBaseline(anyString())).thenReturn(null);
    }

    @Test
    @DisplayName("client supplied Contexa headers are ignored by HCAD scoring")
    void project_clientHeaders_shouldBeIgnoredByScoring() {
        MockHttpServletRequest request = baseRequest();
        request.addHeader("X-Contexa-Recent-Permission-Changes", "admin=true");
        request.addHeader("X-Contexa-Resource-Sensitivity", "HIGH");
        request.addHeader("X-Contexa-Business-Impact", "CRITICAL");

        TrustedHcadContextProjection projection = factory.project(request, authentication());
        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(projection.ignoredInputs()).containsKeys(
                "header.X-Contexa-Recent-Permission-Changes",
                "header.X-Contexa-Resource-Sensitivity",
                "header.X-Contexa-Business-Impact");
        assertThat(projection.promptContextContractVersion())
                .isEqualTo(HcadPromptSecurityContextFieldRegistry.version());
        assertThat(projection.promptContextFieldContracts())
                .containsKey("header.X-Contexa-Recent-Permission-Changes");
        assertThat(projection.promptContextFieldContracts().get("header.X-Contexa-Recent-Permission-Changes"))
                .containsEntry("scoringAllowed", false);
        assertThat(projection.sourceOf("header.X-Contexa-Recent-Permission-Changes"))
                .isEqualTo(HcadTrustedSource.UNTRUSTED_IGNORED);
        assertThat(assessment.anchorSignals()).doesNotContain("RECENT_PERMISSION_CHANGE", "PRIVILEGED_AUTHORIZATION");
        assertThat(assessment.score()).isZero();
    }

    @Test
    @DisplayName("bridge and store derived values are reflected with trusted provenance")
    void project_bridgeAndStoreValues_shouldDriveScoring() {
        MockHttpServletRequest request = baseRequest();
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, authenticationStamp());
        request.setAttribute(BridgeRequestAttributes.AUTHORIZATION_STAMP, authorizationStamp());
        when(securityContextDataStore.getRecentPermissionChangeObservations("tenant-1", "alice", 5))
                .thenReturn(List.of("ROLE_ADMIN granted"));
        when(securityContextDataStore.getRecentSessionActions(anyString(), eq(20)))
                .thenReturn(List.of("AUTHENTICATION_FAILURE", "LOGIN_FAILURE", "AUTHENTICATION_FAILURE"));
        when(hcadDataStore.getRecentRequestCount(anyString(), anyLong(), anyLong())).thenReturn(12);

        TrustedHcadContextProjection projection = factory.project(request, authentication());
        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(projection.sourceOf("authorizationPrivileged")).isEqualTo(HcadTrustedSource.BRIDGE_VERIFIED);
        assertThat(projection.sourceOf("recentPermissionChanges")).isEqualTo(HcadTrustedSource.STORE_DERIVED);
        assertThat(projection.sourceOf("requestBurst")).isEqualTo(HcadTrustedSource.STORE_DERIVED);
        assertThat(assessment.anchorSignals()).contains(
                "FAILED_LOGIN_BURST",
                "RECENT_PERMISSION_CHANGE",
                "PRIVILEGED_AUTHORIZATION",
                "FRESH_MFA_REQUIRED");
        assertThat(assessment.corroboratingSignals()).contains("REQUEST_BURST");
        assertThat(assessment.eligible()).isTrue();
    }

    @Test
    @DisplayName("server-side login failure counters are trusted HCAD anchor evidence")
    void project_loginFailureCounter_shouldDriveFailedLoginBurstAnchor() {
        MockHttpServletRequest request = baseRequest();
        when(securityContextDataStore.getRecentSessionActions(anyString(), eq(20))).thenReturn(List.of());
        when(securityContextDataStore.getSessionLastRequestTime(anyString())).thenReturn(System.currentTimeMillis());
        when(securityContextDataStore.getSessionPreviousPath(anyString())).thenReturn("/admin/dashboard");
        when(hcadDataStore.getRecentLoginFailureCount(eq("alice"), eq("203.0.113.10"), anyLong(), anyLong()))
                .thenReturn(3);
        when(hcadDataStore.getRecentRequestCount(anyString(), anyLong(), anyLong())).thenReturn(12);

        TrustedHcadContextProjection projection = factory.project(request, authentication());
        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(projection.failedLoginBurst()).isEqualTo(3);
        assertThat(projection.sourceOf("failedLoginBurst")).isEqualTo(HcadTrustedSource.STORE_DERIVED);
        assertThat(assessment.anchorSignals()).contains("FAILED_LOGIN_BURST");
        assertThat(assessment.corroboratingSignals()).contains(
                "REQUEST_BURST",
                "RAPID_SEQUENCE",
                "PREVIOUS_PATH_JUMP");
        assertThat(assessment.score()).isGreaterThanOrEqualTo(properties.getPreTrigger().getRedlineScore());
        assertThat(assessment.eligible()).isTrue();
    }

    @Test
    @DisplayName("persisted personal baseline is compared against the trusted request context")
    void project_persistedPersonalBaseline_shouldExposeMaterialMismatch() {
        MockHttpServletRequest request = baseRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36");
        ZonedDateTime now = ZonedDateTime.now(ZoneId.systemDefault());
        when(baselineDataStore.getUserBaseline("alice")).thenReturn(BaselineVector.builder()
                .userId("alice")
                .updateCount(25L)
                .normalIpRanges(new String[]{"10.0.0"})
                .normalAccessHours(new Integer[]{now.getHour()})
                .normalAccessDays(new Integer[]{now.getDayOfWeek().getValue()})
                .frequentPaths(new String[]{"/dashboard"})
                .normalUserAgents(new String[]{"Chrome/120"})
                .normalOperatingSystems(new String[]{"Windows"})
                .normalBrowsers(new String[]{"Chrome"})
                .normalAuthenticationTypes(new String[]{"TOKEN"})
                .build());

        TrustedHcadContextProjection projection = factory.project(request, authentication());
        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(projection.sourceOf("baselineComparison")).isEqualTo(HcadTrustedSource.STORE_DERIVED);
        assertThat(projection.baselineComparison().available()).isTrue();
        assertThat(projection.baselineComparison().established()).isTrue();
        assertThat(projection.baselineComparison().materialMismatch()).isTrue();
        assertThat(projection.baselineComparison().mismatchedDimensions())
                .contains("ipBand", "pathFamily", "authenticationType");
        assertThat(assessment.corroboratingSignals()).contains("BASELINE_MATERIAL_MISMATCH");
        assertThat(assessment.anchorSignals()).doesNotContain("BASELINE_MATERIAL_MISMATCH");
        assertThat(assessment.eligible()).isFalse();
    }

    @Test
    @DisplayName("insufficient personal baseline should be recorded as unavailable evidence and must not trigger mismatch")
    void project_insufficientPersonalBaseline_shouldExplainEvidenceGap() {
        MockHttpServletRequest request = baseRequest();
        when(baselineDataStore.getUserBaseline("alice")).thenReturn(BaselineVector.builder()
                .userId("alice")
                .updateCount(3L)
                .normalIpRanges(new String[]{"10.0.0"})
                .frequentPaths(new String[]{"/dashboard"})
                .normalAuthenticationTypes(new String[]{"TOKEN"})
                .build());

        TrustedHcadContextProjection projection = factory.project(request, authentication());
        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(projection.baselineComparison().available()).isTrue();
        assertThat(projection.baselineComparison().established()).isFalse();
        assertThat(projection.baselineComparison().updateCount()).isEqualTo(3L);
        assertThat(projection.baselineComparison().minSamples()).isEqualTo(20);
        assertThat(projection.baselineComparison().materialMismatch()).isFalse();
        assertThat(projection.baselineComparison().missingDimensions())
                .contains("personalBaselineInsufficientSamples");
        assertThat(assessment.corroboratingSignals()).doesNotContain("BASELINE_MATERIAL_MISMATCH");
        assertThat(assessment.eligible()).isFalse();
    }

    @Test
    @DisplayName("HCAD fast-safe projection values match the prompt context composer values")
    void project_fastSafeProjection_shouldMatchPromptContextComposerValues() {
        MockHttpServletRequest request = baseRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36");
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, authenticationStamp());
        request.setAttribute(BridgeRequestAttributes.AUTHORIZATION_STAMP, authorizationStamp());
        when(securityContextDataStore.getSessionPreviousPath(anyString())).thenReturn("/admin");
        when(hcadDataStore.getRecentRequestCount(anyString(), anyLong(), anyLong())).thenReturn(7);

        TrustedHcadContextProjection projection = factory.project(request, authentication());
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId(projection.userId())
                        .tenantId(projection.tenantId())
                        .organizationId(projection.organizationId())
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId(projection.sessionId())
                        .clientIp(projection.clientIp())
                        .userAgent(request.getHeader("User-Agent"))
                        .authenticationType(projection.authenticationMethod())
                        .authenticationAssurance(projection.authenticationAssurance())
                        .mfaVerified(projection.mfaVerified())
                        .failedLoginAttempts(projection.failedLoginBurst())
                        .recentRequestCount(projection.requestBurst())
                        .build())
                .location(CanonicalSecurityContext.Location.builder()
                        .ipBand(SecuritySemanticNormalizer.normalizeNetwork(projection.clientIp(), null))
                        .build())
                .intent(CanonicalSecurityContext.Intent.builder()
                        .impossibleTravel(projection.impossibleTravel())
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .requestPath(projection.normalizedPath())
                        .httpMethod(projection.method())
                        .actionFamily(SecuritySemanticNormalizer.normalizeActionFamily(projection.method()))
                        .build())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                        .previousPath(projection.previousPath())
                        .burstPattern(projection.rapidSequence())
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .policyId(projection.authorizationPolicyId())
                        .privileged(projection.authorizationPrivileged())
                        .build())
                .build();

        String promptContext = new PromptContextComposer().compose(context);

        assertThat(projection.authenticationMethod()).isEqualTo("MFA_ONLY");
        assertThat(promptContext)
                .contains("AuthenticationType: MFA_ONLY")
                .contains("MfaVerified: false")
                .contains("RecentRequestCount: 7")
                .contains("IpBand: 203.0.113")
                .contains("RequestPath: /admin/reports")
                .contains("CurrentPathFamily: /admin/reports")
                .contains("HttpMethod: GET")
                .contains("ActionFamily: READ")
                .contains("PreviousPath: /admin")
                .contains("PolicyId: policy-1")
                .contains("PrivilegedFlow: true");
    }

    private MockHttpServletRequest baseRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/reports");
        request.setRemoteAddr("203.0.113.10");
        request.getSession(true);
        return request;
    }

    private UsernamePasswordAuthenticationToken authentication() {
        return new UsernamePasswordAuthenticationToken("alice", "n/a", List.of());
    }

    private AuthenticationStamp authenticationStamp() {
        return new AuthenticationStamp(
                "alice",
                "Alice",
                "USER",
                true,
                "mfa",
                "BRIDGE",
                "low",
                false,
                Instant.now().minusSeconds(600),
                "session-bridge",
                List.of("ROLE_USER"),
                Map.of("tenantId", "tenant-1", "organizationId", "org-1"));
    }

    private AuthorizationStamp authorizationStamp() {
        return new AuthorizationStamp(
                "alice",
                "reports",
                "READ",
                AuthorizationEffect.ALLOW,
                true,
                List.of(),
                "policy-1",
                "v1",
                "DB_POLICY",
                Instant.now(),
                List.of("ADMIN"),
                List.of("reports.read"),
                Map.of("verificationRequired", true));
    }
}
