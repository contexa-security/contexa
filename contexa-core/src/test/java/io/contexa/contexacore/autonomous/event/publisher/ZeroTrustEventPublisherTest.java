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
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
                .containsEntry("privileged", true)
                .containsEntry("agentId", "agent-1")
                .containsEntry("objectiveId", "objective-1");
        assertThat((List<String>) event.getPayload().get("effectivePermissions")).contains("REPORT_EXPORT");
        assertThat((List<String>) event.getPayload().get("allowedOperations")).contains("EXPORT");
    }

    private BridgeResolutionResult createBridgeResolutionResult() {
        return new BridgeResolutionResult(
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new AuthenticationStamp("alice", "Alice", "USER", true, "JWT", "HEADER", "HIGH", true, Instant.now(), "session-1", List.of("ROLE_USER"), Map.of("organizationId", "tenant-a")),
                new AuthorizationStamp("alice", "/reports/export", "POST", AuthorizationEffect.ALLOW, true, List.of("report:export"), "policy-1", null, "HEADER", Instant.now(), List.of("ROLE_USER"), List.of("REPORT_EXPORT"), Map.of()),
                new DelegationStamp("alice", "agent-1", true, "objective-1", "Export monthly report", List.of("EXPORT"), List.of("report:monthly"), true, false, null, Map.of()),
                new BridgeCoverageReport(BridgeCoverageLevel.DELEGATION_CONTEXT, 90, Set.of(MissingBridgeContext.AUTHORIZATION_EFFECT))
        );
    }

    private static class SampleService {
        void approve() {
        }
    }
}
