package io.contexa.springbootstartercontexa.service;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.ZeroTrustAnalysisData;
import io.contexa.springbootstartercontexa.event.LlmAnalysisEvent;
import io.contexa.springbootstartercontexa.event.LlmAnalysisEventPublisher;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityTestEvidenceServiceTest {

    @Test
    @DisplayName("requestId 기준 evidence가 즉시 응답, SSE, 서버 truth를 함께 묶는다")
    void bind() {
        ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
        LlmAnalysisEventPublisher publisher = mock(LlmAnalysisEventPublisher.class);
        SecurityTestEvidenceService service = new SecurityTestEvidenceService(
                actionRepository,
                publisher,
                new com.fasterxml.jackson.databind.ObjectMapper(),
                emptyProvider(),
                emptyProvider(),
                emptyProvider(),
                emptyProvider(),
                emptyProvider(),
                emptyProvider(),
                emptyProvider(),
                emptyProvider()
        );

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-001");
        request.addHeader("X-Contexa-Scenario", "ACCOUNT_TAKEOVER");
        request.addHeader("X-Contexa-Expected-Action", "CHALLENGE");
        request.addHeader("X-Contexa-Demo-Run-Id", "run-001");
        request.addHeader("X-Contexa-Demo-Phase", "INITIAL");
        request.addHeader("X-Contexa-Auth-Mode", "header");
        request.addHeader("X-Contexa-Token-Source", "localStorage");
        request.addHeader("X-Contexa-Auth-Carrier", "SESSION_COOKIE + BEARER");
        request.addHeader("X-Contexa-Auth-Subject", "alice");
        request.addHeader("Authorization", "Bearer access-token");
        request.addHeader("X-Forwarded-For", "203.0.113.50");
        request.addHeader("X-Simulated-User-Agent", "Android 10 / Hijacked Session");
        HttpSession session = request.getSession(true);
        session.setAttribute("seed", "ok");

        SecurityTestEvidenceService.RequestRegistration registration =
                service.registerRequest(request, "alice", "sensitive", "resource-001");

        Map<String, Object> responseBody = new LinkedHashMap<>();
        responseBody.put("requestId", registration.getRequestId());
        responseBody.put("sessionId", registration.getSessionId());
        responseBody.put("message", null);
        service.recordResponse(registration.getRequestId(), 200, true, responseBody, 31L);

        when(actionRepository.getAnalysisData("alice")).thenReturn(new ZeroTrustAnalysisData(
                "CHALLENGE",
                0.81,
                0.92,
                "IP changed after authentication",
                2,
                "2026-03-29T10:00:00Z",
                "same session, different environment",
                "same session, different environment",
                "req-001",
                "ctx-123",
                "CHALLENGE"
        ));
        when(publisher.getRecentEvents("alice")).thenReturn(List.of(
                LlmAnalysisEvent.layer1Complete(
                        "alice",
                        "ESCALATE",
                        0.72,
                        0.44,
                        "suspicious takeover signals",
                        "T1078",
                        1200L,
                        Map.of("requestId", "req-001", "correlationId", "req-001")
                )
        ));

        Map<String, Object> evidence = service.getEvidence("alice", "req-001");

        assertThat(evidence.get("requestId")).isEqualTo("req-001");
        assertThat(((Map<?, ?>) evidence.get("request")).get("scenario")).isEqualTo("ACCOUNT_TAKEOVER");
        assertThat(((Map<?, ?>) evidence.get("request")).get("sessionId")).isEqualTo(registration.getSessionId());
        assertThat(((Map<?, ?>) evidence.get("request")).get("authMode")).isEqualTo("header");
        assertThat(((Map<?, ?>) evidence.get("request")).get("tokenSource")).isEqualTo("localStorage");
        assertThat(((Map<?, ?>) evidence.get("request")).get("authCarrier")).isEqualTo("SESSION_COOKIE + BEARER");
        assertThat(((Map<?, ?>) evidence.get("request")).get("authSubjectHint")).isEqualTo("alice");
        assertThat(((Map<?, ?>) evidence.get("request")).get("authorizationHeaderPresent")).isEqualTo(true);
        assertThat(((Map<?, ?>) evidence.get("response")).get("body")).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
                .containsEntry("message", null);
        assertThat(((Map<?, ?>) evidence.get("analysis")).get("requestId")).isEqualTo("req-001");
        assertThat(((Map<?, ?>) evidence.get("context")).get("clientIp")).isEqualTo("203.0.113.50");
        @SuppressWarnings("unchecked")
        Map<String, Object> consistency = (Map<String, Object>) evidence.get("consistency");
        assertThat(consistency)
                .containsEntry("requestRegistered", true)
                .containsEntry("responseCaptured", true)
                .containsEntry("analysisRequestLinked", true)
                .containsEntry("sseLinked", true)
                .containsEntry("contextBindingPresent", true);
    }

    @SuppressWarnings("unchecked")
    private <T> ObjectProvider<T> emptyProvider() {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return provider;
    }
}
