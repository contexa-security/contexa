package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.verification.runtime.OfficialVerificationProbeHeaders;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.HandlerMapping;

import java.lang.reflect.Method;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * R4-C9: the decision path honours no verification probe. The former server-issued capability opens no override or
 * simulation header and no trusted anomaly signal, a fault scenario attribute travels nowhere, and the synthetic user
 * and session attributes name neither the user nor the session. Request attributes keep carrying the model settings an
 * application chose (R4-L7). The test asks the probe headers for the capability only while that class stays for the
 * enterprise (R6).
 */
class ZeroTrustEventPublisherProbeRemovedTest {

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
    }

    @Test
    void theFormerProbeCapabilityOpensNoOverrideAndCarriesNoFault() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
        OfficialVerificationProbeHeaders probe = new OfficialVerificationProbeHeaders();
        probe.setRuntimeOverrideCapability();
        probe.asMap().forEach(request::addHeader);
        request.addHeader("User-Agent", "Mozilla/5.0 real");
        request.addHeader("X-Simulated-User-Agent", "Simulated/1.0");
        request.addHeader("X-Contexa-Temperature", "0.9");
        request.addHeader("X-Contexa-Anomaly-Signal", "credential stuffing");
        request.addHeader("X-Request-ID", "client-chosen-id");
        request.addHeader("X-Contexa-Scenario", "S-PROBE");
        request.addHeader("X-Contexa-Observed-At", "2026-10-14T03:00:00Z");
        request.addHeader("X-PQA-Prompt-Fault", "RAG_SCOPE_SLOT_FAULT");
        request.setAttribute("pqaPromptFaultScenario", "RAG_SCOPE_SLOT_FAULT");

        ZeroTrustSpringEvent event = publish(request, "alice");

        assertThat(event.getUserAgent()).isEqualTo("Mozilla/5.0 real");
        assertThat(event.getPayload())
                .doesNotContainKeys("anomalySignal", "anomalySignalSource", "decisionBoundaryMode",
                        "pqaPromptFaultEnabled", "pqaPromptFaultScenario", "pqaPromptFaultCapability",
                        "pqaPromptFaultSource", "pqaPromptFaultRejected", "pqaPromptFaultRejectedSource")
                .containsEntry("untrustedAnomalySignalClaim", "credential stuffing");
        assertThat(request.getAttribute(RequestInfoExtractor.REQUEST_ID_ATTRIBUTE)).isNotEqualTo("client-chosen-id");
    }

    @Test
    void theSyntheticUserAndSessionAttributesNameNeitherTheUserNorTheSession() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
        String httpSession = request.getSession(true).getId();
        request.setAttribute("officialVerification.requestedUserId", "synthetic-user");
        request.setAttribute("contexa.userId", "synthetic-user");
        request.setAttribute("officialVerification.sessionId", "synthetic-session");
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()));

        ZeroTrustSpringEvent event = publish(request, "alice");

        assertThat(event.getUserId()).isEqualTo("alice");
        assertThat(event.getSessionId()).isEqualTo(httpSession);
    }

    /** R4-L5: the resource URL template is the route the request matched; no verification attribute replaces it. */
    @Test
    void theResourceUrlTemplateIsTheMatchedRouteWhateverTheVerificationAttributeSays() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/reports/7");
        request.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, "/api/reports/{reportId}");
        request.setAttribute("officialVerification.protectableResourceUrl", "/api/security-test/sensitive/{resourceId}");

        ZeroTrustSpringEvent event = publish(request, "alice");

        assertThat(event.getPayload())
                .containsEntry("protectableResourceUrl", "/api/reports/{reportId}")
                .containsEntry("resourceUrlTemplate", "/api/reports/{reportId}");
    }

    /** R4-L6: the round and demo headers of the verification runs are not copied into the event; nothing reads them. */
    @Test
    void theRoundAndDemoHeadersAreNotCopiedIntoTheEvent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
        request.addHeader("X-Contexa-Demo-Run-Id", "bench-7");
        request.addHeader("X-Contexa-Demo-Phase", "ATTACK");
        request.addHeader("X-Contexa-Round-Key", "round-3");
        request.addHeader("X-Contexa-Behavior-Phase", "DRIFT");

        ZeroTrustSpringEvent event = publish(request, "alice");

        assertThat(event.getPayload())
                .doesNotContainKeys("scenario", "demoRunId", "demoPhase", "roundKey", "behaviorPhase");
    }

    @Test
    void aRequestAttributeStillCarriesTheModelSettingsAnApplicationChose() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
        request.setAttribute("temperature", "0.3");

        assertThat(RequestInfoExtractor.extract(request, null).getRuntimeTemperature()).isEqualTo(0.3);
    }

    private static ZeroTrustSpringEvent publish(MockHttpServletRequest request, String user) throws Exception {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = SampleService.class.getDeclaredMethod("protectableApprove");
        when(invocation.getMethod()).thenReturn(method);
        ZeroTrustEventPublisher publisher =
                new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class), new TieredStrategyProperties());
        return publisher.buildMethodAuthorizationEvent(
                invocation, new UsernamePasswordAuthenticationToken(user, "n/a"), true, null);
    }

    private static class SampleService {
        @Protectable
        void protectableApprove() {
        }
    }
}
