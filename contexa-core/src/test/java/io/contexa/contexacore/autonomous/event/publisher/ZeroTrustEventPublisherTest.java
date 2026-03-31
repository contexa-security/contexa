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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ZeroTrustEventPublisherTest {

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("bridge ?멸? ?④낵媛 鍮꾩뼱 ?덉뼱??post-auth ?대깽?몃뒗 ALLOW ?④낵瑜?蹂댁젙???댁븘???쒕떎")
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

        // granted=true??post-auth ?대깽?몃씪硫?authorizationEffect??UNKNOWN?쇰줈 ?⑥쑝硫????쒕떎.
        // ??媛믪씠 鍮꾩뼱 ?덉쑝硫?prompt coverage媛 partial濡??붾뱾由ш퀬 bridge ?덉쭏??怨쇱냼?됯??쒕떎.
        assertThat(event.getPayload())
                .containsEntry("principalType", "USER")
                .containsEntry("authenticationType", "JWT")
                .containsEntry("authenticationAssurance", "HIGH")
                .containsEntry("bridgeCoverageLevel", BridgeCoverageLevel.DELEGATION_CONTEXT.name())
                .containsEntry("bridgeCoverageScore", 100)
                .containsEntry("bridgeCoverageSummary", "Bridge completeness reached authentication, authorization, and delegated execution context for the current request.")
                .containsEntry("bridgeAuthenticationSource", "HEADER")
                .containsEntry("bridgeAuthorizationSource", "HEADER")
                .containsEntry("bridgeDelegationSource", "HEADER")
                .containsEntry("privileged", true)
                .containsEntry("agentId", "agent-1")
                .containsEntry("objectiveId", "objective-1")
                .containsEntry("objectiveFamily", "REPORT_EXPORT")
                .containsEntry("privilegedExportAllowed", false)
                .containsEntry("authorizationEffect", "ALLOW");
        assertThat((List<String>) event.getPayload().getOrDefault("bridgeMissingContexts", List.of()))
                .doesNotContain(MissingBridgeContext.AUTHORIZATION_EFFECT.name());
        assertThat((List<String>) event.getPayload().getOrDefault("bridgeRemediationHints", List.of()))
                .noneMatch(hint -> hint.contains("authorization effect"));
        assertThat((List<String>) event.getPayload().get("effectivePermissions")).contains("report.export");
        assertThat((List<String>) event.getPayload().get("allowedOperations")).contains("EXPORT");
    }

    @Test
    @DisplayName("bridge authorization???놁뼱???몄쬆 ?뺣낫留뚯쑝濡?理쒖냼 沅뚰븳 硫뷀??곗씠?곕뒗 梨꾩썙?몄빞 ?쒕떎")
    void shouldPopulateAuthenticationFallbackMetadataWhenBridgeAuthorizationIsAbsent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.setRequestedSessionId("session-42");
        request.addHeader("User-Agent", "JUnit");
        request.setRemoteAddr("203.0.113.10");
        request.setAttribute("hcad.auth_method", "mfa");
        request.setAttribute("hcad.resource_sensitivity", "HIGH");
        request.setAttribute("hcad.previous_path", "/admin/api/security-test/sensitive/resource-000");
        request.setAttribute("hcad.last_request_interval_ms", 4_200L);
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

        // fallback 硫뷀??곗씠?곌? 梨꾩썙?몄빞 bridge媛 ?쏀븳 ?섍꼍?먯꽌??prompt ?듭떖 ?꾨뱶媛 鍮덇컪?쇰줈 ?⑥? ?딅뒗??
        assertThat(event.getPayload())
                .containsEntry("authMethod", "mfa")
                .containsEntry("mfaVerified", true)
                .containsEntry("resourceSensitivity", "HIGH")
                .containsEntry("previousPath", "/admin/api/security-test/sensitive/resource-000")
                .containsEntry("lastRequestIntervalMs", 4_200L);
        assertThat((List<String>) event.getPayload().get("effectiveRoles")).containsExactly("ANALYST");
        assertThat((List<String>) event.getPayload().get("effectivePermissions")).contains("report.export");
        assertThat((List<String>) event.getPayload().get("authorities")).contains("ROLE_ANALYST", "report.export", "MFA_VERIFIED");
        assertThat(event.getPayload()).containsEntry("authorizationEffect", "ALLOW");
    }
    @Test
    @DisplayName("관측 시각 헤더가 있으면 authorization event timestamp는 현재 시각이 아니라 그 시각을 따라야 한다")
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

        // 이 값이 현재 시각으로 찍히면 benchmark에서 시간대/요일/간격 패턴이 모두 거짓 데이터가 된다.
        assertThat(event.getEventTimestamp()).isEqualTo(Instant.parse("2026-02-03T00:15:00Z"));
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
                        List.of("Populate an explicit authorization effect such as ALLOW or DENY for the current request.")
                )
        );
    }

    private static class SampleService {
        void approve() {
        }
    }
}
