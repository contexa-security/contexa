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
import io.contexa.contexacore.hcad.evaluation.HcadEvaluationWriter;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAssessment;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAttributes;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionBand;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionScorer;
import io.contexa.contexacore.hcad.projection.HcadBaselineComparison;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjection;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjectionFactory;
import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEvidenceReport;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerAttributes;
import io.contexa.contexacore.properties.HcadProperties;
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

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
                .doesNotContainKeys("credentials", "credential", "accessToken", "token", "secret");
        assertThat((List<String>) event.getPayload().getOrDefault("bridgeMissingContexts", List.of()))
                .contains(MissingBridgeContext.AUTHORIZATION_EFFECT.name());
        assertThat((List<String>) event.getPayload().getOrDefault("bridgeRemediationHints", List.of()))
                .anyMatch(hint -> hint.contains("authorization effect"));
        assertThat((List<String>) event.getPayload().get("effectivePermissions")).contains("report.export");
        assertThat((List<String>) event.getPayload().get("allowedOperations")).contains("EXPORT");
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
        request.setAttribute("hcad.auth_method", "mfa");
        request.setAttribute("hcad.resource_sensitivity", "HIGH");
        request.setAttribute("hcad.previous_path", "/admin/api/security-test/sensitive/resource-000");
        request.setAttribute("hcad.last_request_interval_ms", 4_200L);
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
        assertThat((List<String>) event.getPayload().get("effectivePermissions")).contains("report.export");
        assertThat((List<String>) event.getPayload().get("authorities")).contains("ROLE_ANALYST", "report.export", "MFA_VERIFIED");
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
    @DisplayName("prompt budget profile should propagate into authorization event payload")
    void shouldPropagatePromptBudgetProfileIntoAuthorizationEventPayload() throws Exception {
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

        assertThat(event.getPayload()).containsEntry("promptBudgetProfile", "CORTEX_L1_COMPACT");
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

    @Test
    @DisplayName("HCAD observation attributes should propagate without changing decision boundary")
    void shouldPropagateHcadObservationMetadataIntoAuthorizationEventPayload() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/users");
        request.setRequestedSessionId("session-hcad-observation");
        request.addHeader("User-Agent", "JUnit");
        request.setRemoteAddr("203.0.113.15");
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_EVALUATED, true);
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_MODE, "SHADOW");
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_EARLY_ANALYSIS_SCORE, 45);
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_BAND, "HIGH");
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_ELIGIBLE, false);
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_REASON_CODES, List.of("REQUEST_BURST"));
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_RAW_SIGNALS, Map.of("requestBurst", 12));
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID, "eval-rate-limited");
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
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_EVALUATED, true)
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_MODE, "SHADOW")
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 45)
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_BAND, "HIGH")
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, false)
                .containsEntry("hcadEvaluationId", "eval-rate-limited");
        assertThat(event.getPayload()).doesNotContainKey("decisionBoundaryMode");
        assertThat((List<String>) event.getPayload().get(HcadPreProtectablePromotionAttributes.METADATA_REASON_CODES))
                .containsExactly("REQUEST_BURST");
        assertThat((Map<String, Object>) event.getPayload().get(HcadPreProtectablePromotionAttributes.METADATA_RAW_SIGNALS))
                .containsEntry("requestBurst", 12);
    }

    @Test
    @DisplayName("Protectable authorization should attach observed HCAD evidence when the request was not the window owner")
    void shouldAttachProtectableHcadObservationWhenWindowWasAlreadyObserved() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/users");
        request.setRequestedSessionId("session-hcad-protectable-observed");
        request.addHeader("User-Agent", "JUnit");
        request.setRemoteAddr("203.0.113.20");
        request.setAttribute("hcad.actorSessionKey", "actor-window-1");
        request.setAttribute("hcad.windowId", "window-1");
        request.setAttribute("hcad.windowRequestCount", 4);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        TrustedHcadContextProjection projection = new TrustedHcadContextProjection(
                "alice",
                null,
                null,
                "session-hcad-protectable-observed",
                "binding-1",
                "GET",
                "/admin/users",
                "203.0.113.20",
                "password",
                null,
                false,
                null,
                null,
                null,
                null,
                List.of(),
                0,
                0,
                false,
                "/admin/dashboard",
                false,
                0.95d,
                true,
                new HcadBaselineComparison(
                        true,
                        true,
                        40L,
                        20,
                        4,
                        0,
                        1.0d,
                        false,
                        List.of("method", "path"),
                        List.of(),
                        List.of(),
                        Map.of("path", "/admin/users"),
                        Map.of("path", "/admin/users"),
                        null),
                "hcad-test",
                Map.of(),
                Map.of(),
                Map.of());
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                10,
                HcadPreProtectablePromotionBand.LOW,
                false,
                List.of(),
                List.of("BASELINE_MATCH"),
                List.of("BASELINE_MATCH"),
                "No trusted risk signal",
                "hcad-test",
                Map.of("baselineComparison", projection.baselineComparison()));
        TrustedHcadContextProjectionFactory projectionFactory = mock(TrustedHcadContextProjectionFactory.class);
        HcadPreProtectablePromotionScorer scorer = mock(HcadPreProtectablePromotionScorer.class);
        HcadEvaluationWriter writer = mock(HcadEvaluationWriter.class);
        when(projectionFactory.project(eq(request), any())).thenReturn(projection);
        when(scorer.score(projection)).thenReturn(assessment);
        when(writer.recordCandidate(eq(HcadPreTriggerMode.SHADOW), any(PendingAnomalyEvidenceReport.class)))
                .thenReturn("eval-protectable-observed");

        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("protectableApprove");
        when(invocation.getMethod()).thenReturn(method);

        ZeroTrustEventPublisher publisher =
                new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class), new TieredStrategyProperties());
        setField(publisher, "trustedHcadContextProjectionFactory", projectionFactory);
        setField(publisher, "hcadPreProtectablePromotionScorer", scorer);
        setField(publisher, "hcadEvaluationWriter", writer);
        setField(publisher, "hcadProperties", new HcadProperties());

        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null);

        assertThat(event.getPayload())
                .containsEntry("protectableDeclared", true)
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_EVALUATED, true)
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 10)
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_BAND, "LOW")
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, false)
                .doesNotContainKey("hcadEvaluationId");
        verify(writer, never()).recordCandidate(eq(HcadPreTriggerMode.SHADOW), any(PendingAnomalyEvidenceReport.class));
    }

    @Test
    @DisplayName("already evaluated ineligible Protectable request should not persist HCAD candidate")
    void shouldNotPersistAlreadyEvaluatedIneligibleProtectableObservationBeforeMethodEvent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/test/hcad/live/accounts/123");
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("User-Agent", "JUnit");
        request.setAttribute("hcad.actorSessionKey", "actor-window-existing");
        request.setAttribute("hcad.windowId", "window-existing");
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_EVALUATED, true);
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_MODE, "SHADOW");
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_SCORE, 10);
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_EARLY_ANALYSIS_SCORE, 10);
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_BAND, "LOW");
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_ELIGIBLE, false);
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_ANCHOR_SIGNALS, List.of());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_CORROBORATING_SIGNALS, List.of("BASELINE_MATCH"));
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_REASON_CODES, List.of("BASELINE_MATCH"));
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_SUMMARY, "No trusted risk signal");
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_VERSION, "hcad-test");
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_RAW_SIGNALS,
                Map.of("baselineComparison", Map.of("available", true, "established", true)));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        TrustedHcadContextProjection projection = new TrustedHcadContextProjection(
                "alice",
                "tenant-a",
                "org-a",
                "session-a",
                "binding-a",
                "GET",
                "/contexa/test/hcad/live/accounts/123",
                "127.0.0.1",
                "password",
                null,
                false,
                null,
                null,
                null,
                null,
                List.of(),
                0,
                1,
                false,
                "/contexa/admin/dashboard",
                false,
                0.95d,
                true,
                new HcadBaselineComparison(
                        true,
                        true,
                        40L,
                        20,
                        4,
                        0,
                        1.0d,
                        false,
                        List.of("method", "path"),
                        List.of(),
                        List.of(),
                        Map.of("path", "/contexa/test/hcad/live/accounts/{accountId}"),
                        Map.of("path", "/contexa/test/hcad/live/accounts/{accountId}"),
                        null),
                "hcad-test",
                Map.of(),
                Map.of(),
                Map.of());
        TrustedHcadContextProjectionFactory projectionFactory = mock(TrustedHcadContextProjectionFactory.class);
        HcadPreProtectablePromotionScorer scorer = mock(HcadPreProtectablePromotionScorer.class);
        HcadEvaluationWriter writer = mock(HcadEvaluationWriter.class);
        when(projectionFactory.project(eq(request), any())).thenReturn(projection);
        when(writer.recordCandidate(eq(HcadPreTriggerMode.SHADOW), any(PendingAnomalyEvidenceReport.class)))
                .thenReturn("eval-existing-observation");

        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("protectableApprove");
        when(invocation.getMethod()).thenReturn(method);

        ZeroTrustEventPublisher publisher =
                new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class), new TieredStrategyProperties());
        setField(publisher, "trustedHcadContextProjectionFactory", projectionFactory);
        setField(publisher, "hcadPreProtectablePromotionScorer", scorer);
        setField(publisher, "hcadEvaluationWriter", writer);
        setField(publisher, "hcadProperties", new HcadProperties());

        ZeroTrustSpringEvent event = publisher.buildMethodAuthorizationEvent(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null);

        assertThat(event.getPayload())
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_EVALUATED, true)
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 10)
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_BAND, "LOW")
                .containsEntry(HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, false)
                .doesNotContainKey("hcadEvaluationId");
        verify(scorer, never()).score(any());
        verify(writer, never()).recordCandidate(eq(HcadPreTriggerMode.SHADOW), any(PendingAnomalyEvidenceReport.class));
    }
    @Test
    @DisplayName("pre-protectable threat publication should include bridge metadata when available")
    void shouldIncludeBridgeMetadataInPreProtectableThreatPayload() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/export/reports");
        request.setRequestedSessionId("session-pre-bridge");
        request.addHeader("User-Agent", "JUnit");
        request.setRemoteAddr("10.0.0.12");
        request.setAttribute(BridgeRequestAttributes.RESOLUTION_RESULT, createBridgeResolutionResult());
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        ApplicationEventPublisher applicationEventPublisher = mock(ApplicationEventPublisher.class);
        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(applicationEventPublisher, new TieredStrategyProperties());

        publisher.publishPreProtectableThreat("alice", Map.of("reasonCodes", List.of("IMPOSSIBLE_TRAVEL", "NEW_DEVICE")));

        ArgumentCaptor<ZeroTrustSpringEvent> captor = ArgumentCaptor.forClass(ZeroTrustSpringEvent.class);
        verify(applicationEventPublisher).publishEvent(captor.capture());
        assertThat(captor.getValue().getPayload())
                .containsEntry("bridgeCoverageLevel", BridgeCoverageLevel.DELEGATION_CONTEXT.name())
                .containsEntry("bridgeAuthenticationSource", "HEADER")
                .containsEntry("bridgeAuthorizationSource", "HEADER")
                .containsEntry("bridgeDelegationSource", "HEADER");
    }
    @Test
    @DisplayName("same-request pre-trigger marker should suppress method authorization publication")
    void shouldSuppressMethodAuthorizationEventWhenPreTriggerMarkerExists() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/export/reports");
        request.setRequestedSessionId("session-pre-trigger");
        request.addHeader("User-Agent", "JUnit");
        request.setRemoteAddr("203.0.113.11");
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGERED, true);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        ApplicationEventPublisher applicationEventPublisher = mock(ApplicationEventPublisher.class);
        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(applicationEventPublisher, new TieredStrategyProperties());

        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("approve");
        when(invocation.getMethod()).thenReturn(method);

        publisher.publishMethodAuthorization(
                invocation,
                new UsernamePasswordAuthenticationToken("alice", "n/a"),
                true,
                null
        );

        verify(applicationEventPublisher, never()).publishEvent(any());
    }
    private BridgeResolutionResult createBridgeResolutionResult() {
        return new BridgeResolutionResult(
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new AuthenticationStamp("alice", "Alice", "USER", true, "JWT", "HEADER", "HIGH", true, Instant.now(), "session-1", List.of("ROLE_USER"), Map.of(
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
                        List.of("ROLE_USER"),
                        List.of(
                                "PermissionAuthority{authority='REPORT_EXPORT', permissionId=7}",
                                "RoleAuthority{authority='ROLE_USER', roleId=1}",
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

    private void setField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static class SampleService {
        void approve() {
        }

        @Protectable
        void protectableApprove() {
        }
    }
}






