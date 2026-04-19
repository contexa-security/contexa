package io.contexa.contexacore.autonomous.event.publisher;

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
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerAttributes;
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

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
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
                .containsEntry("authorizationEffectProvenance", "METHOD_INVOCATION_RESULT");
        assertThat((List<String>) event.getPayload().getOrDefault("bridgeMissingContexts", List.of()))
                .contains(MissingBridgeContext.AUTHORIZATION_EFFECT.name());
        assertThat((List<String>) event.getPayload().getOrDefault("bridgeRemediationHints", List.of()))
                .anyMatch(hint -> hint.contains("authorization effect"));
        assertThat((List<String>) event.getPayload().get("effectivePermissions")).contains("report.export");
        assertThat((List<String>) event.getPayload().get("allowedOperations")).contains("EXPORT");
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
    @DisplayName("generic requested model header should propagate into authorization event payload")
    void shouldPropagateRequestedModelHeaderIntoAuthorizationEventPayload() throws Exception {
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
                .containsEntry("requestedModelId", "qwen2.5:7b")
                .containsEntry("preferredModel", "qwen2.5:7b");
    }
    @Test
    @DisplayName("canonical runtime headers should propagate into authorization event payload")
    void shouldPropagateCanonicalRuntimeHeadersIntoAuthorizationEventPayload() throws Exception {
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
                .containsEntry("decisionBoundaryMode", "RUNTIME_MODEL_SELECTION")
                .containsEntry("requestedModelId", "qwen3:8b")
                .containsEntry("preferredModel", "qwen3:8b")
                .containsEntry("temperature", 0.0d)
                .containsEntry("topP", 0.2d)
                .containsEntry("seed", 7)
                .containsEntry("maxTokens", 96)
                .containsEntry("disableRetries", true)
                .containsEntry("disableOllamaThinking", true);
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
                new AuthenticationStamp("alice", "Alice", "USER", true, "JWT", "HEADER", "HIGH", true, Instant.now(), "session-1", List.of("ROLE_USER"), Map.of("organizationId", "tenant-a")),
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
                        Map.of()),
                new DelegationStamp("alice", "agent-1", true, "objective-1", "REPORT_EXPORT", "Export monthly report", List.of("EXPORT"), List.of("report:monthly"), true, false, false, null, Map.of("delegationResolver", "HEADER")),
                new BridgeCoverageReport(
                        BridgeCoverageLevel.DELEGATION_CONTEXT,
                        90,
                        Set.of(MissingBridgeContext.AUTHORIZATION_EFFECT),
                        "Bridge resolved authentication, authorization, and delegated execution context for the current request.",
                        List.of("Populate an explicit authorization effect such as ALLOW or DENY for the current request."))
        );
    }

    private BridgeResolutionResult createBridgeResolutionResultWithoutDelegatedFlag() {
        return new BridgeResolutionResult(
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.11", "JUnit", "session-2", "request-2", "/reports/export", null, false, Instant.now()),
                new AuthenticationStamp("alice", "Alice", "USER", true, "JWT", "HEADER", "HIGH", true, Instant.now(), "session-2", List.of("ROLE_USER"), Map.of("organizationId", "tenant-a")),
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
    }
}






