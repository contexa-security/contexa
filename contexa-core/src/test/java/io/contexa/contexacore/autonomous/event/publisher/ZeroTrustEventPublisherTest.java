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
package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageLevel;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageReport;
import io.contexa.contexacommon.security.bridge.coverage.MissingBridgeContext;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.HandlerMapping;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ZeroTrustEventPublisherTest {

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("bridge completeness should remain transparent when authorization effect is synthesized")
    void shouldIncludeBridgeMetadataInAuthorizationEventPayload() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/reports/export");
        request.setRequestedSessionId("session-1");
        request.addHeader("User-Agent", "JUnit");
        request.addHeader("X-Simulated-User-Agent", "JUnit /ato");
        request.setRemoteAddr("10.0.0.10");
        request.setAttribute(BridgeRequestAttributes.RESOLUTION_RESULT, createBridgeResolutionResult());
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("approve");
        when(invocation.getMethod()).thenReturn(method);

        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class), new TieredStrategyProperties());
        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null
        );

        assertThat(event.getUserAgent()).isEqualTo("JUnit /ato");
        assertThat(event.getPayload())
                .containsEntry("principalType", "USER")
                .containsEntry("authenticationType", "JWT")
                .containsEntry("authenticationAssurance", "HIGH")
                .containsEntry("tenantId", "tenant-a")
                .containsEntry("organizationId", "org-a")
                .containsEntry("bridgeCoverageLevel", BridgeCoverageLevel.DELEGATION_CONTEXT.name())
                .containsEntry("bridgeCoverageScore", 90)
                .containsEntry("bridgeCoverageSummary", "Bridge resolved authentication, authorization, and delegated execution context for the current request.")
                .containsEntry("bridgeAuthenticationSource", "HEADER")
                .containsEntry("bridgeAuthorizationSource", "HEADER")
                .containsEntry("bridgeDelegationSource", "HEADER")
                .containsEntry("privileged", true)
                .containsEntry("agentId", "agent-1")
                .containsEntry("objectiveId", "objective-1")
                .containsEntry("objectiveFamily", "REPORT_EXPORT")
                .containsEntry("privilegedExportAllowed", false)
                .containsEntry("authorizationEffect", "ALLOW")
                .containsEntry("authorizationEffectProvenance", "METHOD_INVOCATION_RESULT")
                .containsEntry("bridgeAuthorizationEffect", "UNKNOWN")
                .containsEntry("authorizationEffectFallbackFrom", "UNKNOWN")
                .containsEntry("methodAuthorizationGranted", true)
                .containsEntry("policyId", "policy-1")
                .containsEntry("contextBindingHash", SessionFingerprintUtil.generateContextBindingHash(
                        "session-1", "10.0.0.10", "JUnit"))
                .doesNotContainKeys("credentials", "credential", "accessToken", "token", "secret");
        assertThat((List<String>) event.getPayload().getOrDefault("bridgeMissingContexts", List.of()))
                .contains(MissingBridgeContext.AUTHORIZATION_EFFECT.name());
        assertThat((List<String>) event.getPayload().getOrDefault("bridgeRemediationHints", List.of()))
                .anyMatch(hint -> hint.contains("authorization effect"));
        assertThat((List<String>) event.getPayload().get("effectiveRoles")).containsExactly("USER");
        assertThat((List<String>) event.getPayload().get("effectivePermissions"))
                .contains("report.export")
                .doesNotContain("role.pending.analysis");
        assertThat((List<String>) event.getPayload().get("authorities"))
                .doesNotContain("ROLE_PENDING_ANALYSIS");
        assertThat((List<String>) event.getPayload().get("allowedOperations")).contains("EXPORT");
    }

    @Test
    @DisplayName("server-verified protectable URL should override the MVC probe route")
    void shouldPreferServerVerifiedProtectableResourceUrl() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET",
                "/contexa/admin/api/enterprise/verification/runtime/probe/sensitive/resource-001");
        request.setAttribute(
                HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE,
                "/contexa/admin/api/enterprise/verification/runtime/probe/sensitive/{resourceId}");
        request.setAttribute(
                "officialVerification.protectableResourceUrl",
                "/api/security-test/sensitive/{resourceId}");
        request.addHeader("X-Contexa-Anomaly-Signal", "CONFIRMED_CREDENTIAL_EXFILTRATION");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("protectableApprove");
        when(invocation.getMethod()).thenReturn(method);

        ZeroTrustEventPublisher publisher =
                new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class), new TieredStrategyProperties());
        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null);

        assertThat(event.getPayload())
                .containsEntry("protectableResourceUrl", "/api/security-test/sensitive/{resourceId}")
                .containsEntry("resourceUrlTemplate", "/api/security-test/sensitive/{resourceId}")
                .containsEntry("anomalySignal", "CONFIRMED_CREDENTIAL_EXFILTRATION")
                .containsEntry("anomalySignalSource", "OFFICIAL_VERIFICATION_INTERNAL")
                .containsEntry(
                        "resourceId",
                        SampleService.class.getName() + "#protectableApprove");
    }

    @Test
    @DisplayName("stored MFA and login failure context should reach a protectable event")
    void shouldPopulateStoredAuthenticationContext() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
        request.setRemoteAddr("203.0.113.15");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(
                SampleService.class.getDeclaredMethod("protectableApprove"));
        SecurityContextDataStore dataStore = mock(SecurityContextDataStore.class);
        when(dataStore.isMfaVerified("alice")).thenReturn(true);
        when(dataStore.getRecentLoginFailureCount(
                eq("alice"), eq("203.0.113.15"), anyLong(), anyLong()))
                .thenReturn(3);

        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(
                mock(ApplicationEventPublisher.class),
                new TieredStrategyProperties(),
                dataStore,
                new SecurityPlaneProperties());
        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null);

        assertThat(event.getPayload())
                .containsEntry("mfaVerified", true)
                .containsEntry("failedLoginAttempts", 3);
    }

    @Test
    @DisplayName("explicit bridge deny and its policy evidence should survive a granted method result")
    void shouldPreserveExplicitBridgeDenyWhenMethodInvocationIsGranted() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/reports/export");
        request.setAttribute(
                BridgeRequestAttributes.RESOLUTION_RESULT,
                createBridgeResolutionResultWithEffect(AuthorizationEffect.DENY));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(SampleService.class.getDeclaredMethod("approve"));

        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(
                mock(ApplicationEventPublisher.class),
                new TieredStrategyProperties());
        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null);

        assertThat(event.getPayload())
                .containsEntry("authorizationEffect", "DENY")
                .containsEntry("bridgeAuthorizationEffect", "DENY")
                .containsEntry("authorizationEffectProvenance", "BRIDGE_AUTHORIZATION_STAMP")
                .containsEntry("authorizationDecisionConflict", "METHOD_GRANTED_WITH_BRIDGE_DENY")
                .containsEntry("methodAuthorizationGranted", true)
                .containsEntry("policyId", "policy-1");
        assertThat((List<String>) event.getPayload().get("scopeTags")).contains("report:export");
    }

    @Test
    @DisplayName("delegation objective lineage should survive even when delegated flag is false")
    void shouldPreserveDelegationObjectiveLineageWhenDelegationStampIsNotMarkedDelegated() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/reports/export");
        request.setRequestedSessionId("session-2");
        request.addHeader("User-Agent", "JUnit");
        request.setRemoteAddr("10.0.0.11");
        request.setAttribute(BridgeRequestAttributes.RESOLUTION_RESULT, createBridgeResolutionResultWithoutDelegatedFlag());
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("approve");
        when(invocation.getMethod()).thenReturn(method);

        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class), new TieredStrategyProperties());
        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null
        );

        assertThat(event.getPayload())
                .containsEntry("bridgeDelegationSource", "HEADER")
                .containsEntry("delegated", false)
                .containsEntry("objectiveId", "objective-2")
                .containsEntry("objectiveFamily", "REPORT_EXPORT")
                .containsEntry("objectiveSummary", "Export monthly report")
                .containsEntry("authorizationEffect", "ALLOW")
                .containsEntry("authorizationEffectProvenance", "BRIDGE_AUTHORIZATION_STAMP");
        assertThat((List<String>) event.getPayload().get("allowedOperations")).contains("EXPORT");
        assertThat((List<String>) event.getPayload().get("allowedResources")).contains("report:monthly");
    }

    @Test
    @DisplayName("fallback metadata should populate when bridge authorization is absent")
    void shouldPopulateAuthenticationFallbackMetadataWhenBridgeAuthorizationIsAbsent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.setRequestedSessionId("session-42");
        request.addHeader("User-Agent", "JUnit");
        request.setRemoteAddr("203.0.113.10");
        request.setAttribute("authenticationType", "mfa");
        request.setAttribute("resourceSensitivity", "HIGH");
        request.setAttribute("previousPath", "/admin/api/security-test/sensitive/resource-000");
        request.setAttribute("lastRequestIntervalMs", 4_200L);
        request.setAttribute("currentResourceFamily", "SENSITIVE");
        request.setAttribute("currentActionFamily", "READ");
        request.setAttribute("expectedResourceFamilies", List.of("SENSITIVE"));
        request.setAttribute("expectedActionFamilies", List.of("READ"));
        request.setAttribute("recentPermissionChanges", List.of("NONE_RECORDED"));
        request.setAttribute("approvalRequired", false);
        request.setAttribute("approvalGranted", false);
        request.setAttribute("approvalMissing", false);
        request.setAttribute("approvalStatus", "NOT_APPLICABLE");
        request.setAttribute("delegated", false);
        request.setAttribute("objectiveDrift", false);
        request.setAttribute("objectiveDriftSummary", "NOT_APPLICABLE: direct user request is not delegated.");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("approve");
        when(invocation.getMethod()).thenReturn(method);

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                "alice",
                "n/a",
                List.of(
                        new SimpleGrantedAuthority("ROLE_ANALYST"),
                        new SimpleGrantedAuthority("ROLE_PENDING_ANALYSIS"),
                        new SimpleGrantedAuthority("report.export"),
                        new SimpleGrantedAuthority("MFA_VERIFIED"))
        );

        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class), new TieredStrategyProperties());
        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(invocation, authentication, true, null);

        assertThat(event.getPayload())
                .containsEntry("authMethod", "mfa")
                .containsEntry("mfaVerified", true)
                .containsEntry("resourceSensitivity", "HIGH")
                .containsEntry("previousPath", "/admin/api/security-test/sensitive/resource-000")
                .containsEntry("lastRequestIntervalMs", 4_200L)
                .containsEntry("currentResourceFamily", "SENSITIVE")
                .containsEntry("currentActionFamily", "READ")
                .containsEntry("approvalRequired", false)
                .containsEntry("approvalGranted", false)
                .containsEntry("approvalMissing", false)
                .containsEntry("approvalStatus", "NOT_APPLICABLE")
                .containsEntry("delegated", false)
                .containsEntry("objectiveDrift", false)
                .containsEntry("objectiveDriftSummary", "NOT_APPLICABLE: direct user request is not delegated.")
                .containsEntry("authorizationEffect", "ALLOW")
                .containsEntry("authorizationEffectProvenance", "METHOD_INVOCATION_RESULT");
        assertThat((List<String>) event.getPayload().get("expectedResourceFamilies")).containsExactly("SENSITIVE");
        assertThat((List<String>) event.getPayload().get("expectedActionFamilies")).containsExactly("READ");
        assertThat((List<String>) event.getPayload().get("recentPermissionChanges")).containsExactly("NONE_RECORDED");
        assertThat((List<String>) event.getPayload().get("effectiveRoles")).containsExactly("ANALYST");
        assertThat((List<String>) event.getPayload().get("effectivePermissions"))
                .contains("report.export")
                .doesNotContain("role.pending.analysis");
        assertThat((List<String>) event.getPayload().get("authorities")).contains("ROLE_ANALYST", "report.export", "MFA_VERIFIED");
        assertThat((List<String>) event.getPayload().get("authorities")).doesNotContain("ROLE_PENDING_ANALYSIS");
    }

    @Test
    @DisplayName("runtime action and role authorities should not be projected as permissions")
    void shouldNotProjectRoleAuthoritiesAsPermissions() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/view");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(SampleService.class.getDeclaredMethod("approve"));
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                "alice",
                "n/a",
                List.of(
                        new SimpleGrantedAuthority("ROLE_ANALYST"),
                        new SimpleGrantedAuthority("ROLE_PENDING_ANALYSIS")));

        ZeroTrustSpringEvent event = new ZeroTrustEventPublisher(
                mock(ApplicationEventPublisher.class),
                new TieredStrategyProperties()).buildMethodAuthorizationEvent(invocation, authentication, true, null);

        assertThat((List<String>) event.getPayload().get("effectiveRoles")).containsExactly("ANALYST");
        assertThat(event.getPayload()).doesNotContainKey("effectivePermissions");
        assertThat((List<String>) event.getPayload().get("authorities"))
                .containsExactly("ROLE_ANALYST");
    }

    @Test
    @DisplayName("observed-at header should control authorization event timestamp")
    void shouldUseObservedAtForAuthorizationEventTimestamp() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.setRequestedSessionId("session-observed-at");
        request.addHeader("User-Agent", "JUnit");
        request.addHeader("X-Contexa-Observed-At", "2026-02-03T09:15:00+09:00");
        request.setRemoteAddr("203.0.113.10");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("approve");
        when(invocation.getMethod()).thenReturn(method);

        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class), new TieredStrategyProperties());
        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null
        );

        assertThat(event.getEventTimestamp()).isEqualTo(Instant.parse("2026-02-03T00:15:00Z"));
    }

    @Test
    @DisplayName("untrusted prompt budget profile header should not affect authorization event payload")
    void shouldIgnorePromptBudgetProfileHeaderInAuthorizationEventPayload() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.setRequestedSessionId("session-budget");
        request.addHeader("User-Agent", "JUnit");
        request.addHeader("X-Contexa-Prompt-Budget-Profile", "CORTEX_L1_COMPACT");
        request.setRemoteAddr("203.0.113.10");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("approve");
        when(invocation.getMethod()).thenReturn(method);

        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class), new TieredStrategyProperties());
        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null
        );

        assertThat(event.getPayload()).doesNotContainKey("promptBudgetProfile");
    }

    @Test
    @DisplayName("generic requested model header should not propagate into ordinary authorization event payload")
    void shouldIgnoreRequestedModelHeaderForOrdinaryAuthorizationEventPayload() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.setRequestedSessionId("session-generic-model");
        request.addHeader("User-Agent", "JUnit");
        request.addHeader("X-Contexa-Model-Id", "qwen2.5:7b");
        request.setRemoteAddr("203.0.113.10");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("approve");
        when(invocation.getMethod()).thenReturn(method);

        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class), new TieredStrategyProperties());
        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null
        );

        assertThat(event.getPayload())
                .doesNotContainKeys("requestedModelId", "preferredModel");
    }

    @Test
    @DisplayName("canonical runtime headers should not propagate into ordinary authorization event payload")
    void shouldIgnoreCanonicalRuntimeHeadersForOrdinaryAuthorizationEventPayload() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.setRequestedSessionId("session-runtime-selection");
        request.addHeader("User-Agent", "JUnit");
        request.addHeader("X-Contexa-Model-Id", "qwen3:8b");
        request.addHeader("X-Contexa-Temperature", "0.0");
        request.addHeader("X-Contexa-Top-P", "0.2");
        request.addHeader("X-Contexa-Seed", "7");
        request.addHeader("X-Contexa-Max-Tokens", "96");
        request.addHeader("X-Contexa-Disable-Retries", "true");
        request.addHeader("X-Contexa-Disable-Ollama-Thinking", "true");
        request.setRemoteAddr("203.0.113.10");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("approve");
        when(invocation.getMethod()).thenReturn(method);

        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class), new TieredStrategyProperties());
        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null
        );

        assertThat(event.getPayload())
                .doesNotContainKeys(
                        "decisionBoundaryMode",
                        "requestedModelId",
                        "preferredModel",
                        "temperature",
                        "topP",
                        "seed",
                        "maxTokens",
                        "disableRetries",
                        "disableOllamaThinking");
    }

    private BridgeResolutionResult createBridgeResolutionResult() {
        return new BridgeResolutionResult(
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new AuthenticationStamp("alice", "Alice", "USER", true, "JWT", "HEADER", "HIGH", true, Instant.now(), "session-1", List.of("ROLE_USER", "ROLE_PENDING_ANALYSIS"), Map.of(
                        "tenantId", "tenant-a",
                        "organizationId", "org-a",
                        "credentials", "must-not-leak",
                        "accessToken", "must-not-leak",
                        "secret", "must-not-leak")),
                new AuthorizationStamp(
                        "alice",
                        "/reports/export",
                        "POST",
                        AuthorizationEffect.UNKNOWN,
                        true,
                        List.of("report:export"),
                        "policy-1",
                        null,
                        "HEADER",
                        Instant.now(),
                        List.of("ROLE_USER", "ROLE_PENDING_ANALYSIS"),
                        List.of(
                                "PermissionAuthority{authority='REPORT_EXPORT', permissionId=7}",
                                "RoleAuthority{authority='ROLE_USER', roleId=1}",
                                "ROLE_PENDING_ANALYSIS",
                                "/reports/export"),
                        Map.of("token", "must-not-leak", "secret", "must-not-leak")),
                new DelegationStamp("alice", "agent-1", true, "objective-1", "REPORT_EXPORT", "Export monthly report", List.of("EXPORT"), List.of("report:monthly"), true, false, false, null, Map.of(
                        "delegationResolver", "HEADER",
                        "credential", "must-not-leak")),
                new BridgeCoverageReport(
                        BridgeCoverageLevel.DELEGATION_CONTEXT,
                        90,
                        Set.of(MissingBridgeContext.AUTHORIZATION_EFFECT),
                        "Bridge resolved authentication, authorization, and delegated execution context for the current request.",
                        List.of("Populate an explicit authorization effect such as ALLOW or DENY for the current request."))
        );
    }

    private BridgeResolutionResult createBridgeResolutionResultWithEffect(AuthorizationEffect effect) {
        BridgeResolutionResult baseline = createBridgeResolutionResult();
        AuthorizationStamp authorization = baseline.authorizationStamp();
        return new BridgeResolutionResult(
                baseline.requestContext(),
                baseline.authenticationStamp(),
                new AuthorizationStamp(
                        authorization.subjectId(),
                        authorization.resourceId(),
                        authorization.action(),
                        effect,
                        authorization.privileged(),
                        authorization.scopeTags(),
                        authorization.policyId(),
                        authorization.policyVersion(),
                        authorization.decisionSource(),
                        authorization.decisionTime(),
                        authorization.effectiveRoles(),
                        authorization.effectiveAuthorities(),
                        authorization.attributes()),
                baseline.delegationStamp(),
                baseline.coverageReport());
    }

    private BridgeResolutionResult createBridgeResolutionResultWithoutDelegatedFlag() {
        return new BridgeResolutionResult(
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.11", "JUnit", "session-2", "request-2", "/reports/export", null, false, Instant.now()),
                new AuthenticationStamp("alice", "Alice", "USER", true, "JWT", "HEADER", "HIGH", true, Instant.now(), "session-2", List.of("ROLE_USER"), Map.of(
                        "tenantId", "tenant-a",
                        "organizationId", "org-a")),
                new AuthorizationStamp(
                        "alice",
                        "/reports/export",
                        "POST",
                        AuthorizationEffect.ALLOW,
                        true,
                        List.of("report:export"),
                        "policy-1",
                        null,
                        "HEADER",
                        Instant.now(),
                        List.of("ROLE_USER"),
                        List.of("REPORT_EXPORT"),
                        Map.of()),
                new DelegationStamp("alice", "agent-1", false, "objective-2", "REPORT_EXPORT", "Export monthly report", List.of("EXPORT"), List.of("report:monthly"), true, false, false, null, Map.of("delegationResolver", "HEADER")),
                new BridgeCoverageReport(
                        BridgeCoverageLevel.AUTHORIZATION_CONTEXT,
                        80,
                        Set.of(MissingBridgeContext.DELEGATION),
                        "Bridge completeness reached authentication and authorization context, but delegated execution metadata is incomplete for this request.",
                        List.of("Populate explicit delegated execution metadata when the request is acting on behalf of another principal or scoped objective."))
        );
    }

    private static class SampleService {
        void approve() {
        }

        @Protectable
        void protectableApprove() {
        }
    }
}






