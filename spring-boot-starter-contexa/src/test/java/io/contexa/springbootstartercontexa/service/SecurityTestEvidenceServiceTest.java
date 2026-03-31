package io.contexa.springbootstartercontexa.service;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.ZeroTrustAnalysisData;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
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
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityTestEvidenceServiceTest {

    @Test
    @DisplayName("동일 requestId로 즉시 응답 SSE 서버 truth 컨텍스트가 하나의 증거 체인으로 연결되어야 한다")
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

        // 브라우저 화면과 서버 truth가 requestId 기준으로 연결되어야
        // "지금 보고 있는 값이 실제 분석 흐름과 같은가"를 입증할 수 있다.
        assertThat(evidence.get("requestId")).isEqualTo("req-001");
        assertThat(((Map<?, ?>) evidence.get("request")).get("scenario")).isEqualTo("ACCOUNT_TAKEOVER");
        assertThat(((Map<?, ?>) evidence.get("request")).get("sessionId")).isEqualTo(registration.getSessionId());
        assertThat(((Map<?, ?>) evidence.get("request")).get("authMode")).isEqualTo("header");
        assertThat(((Map<?, ?>) evidence.get("request")).get("tokenSource")).isEqualTo("localStorage");
        assertThat(((Map<?, ?>) evidence.get("request")).get("authCarrier")).isEqualTo("SESSION_COOKIE + BEARER");
        assertThat(((Map<?, ?>) evidence.get("request")).get("authSubjectHint")).isEqualTo("alice");
        assertThat(((Map<?, ?>) evidence.get("request")).get("authorizationHeaderPresent")).isEqualTo(true);
        assertThat(((Map<?, ?>) evidence.get("response")).get("body"))
                .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
                .containsEntry("message", null);
        assertThat(((Map<?, ?>) evidence.get("analysis")).get("requestId")).isEqualTo("req-001");
        assertThat(((Map<?, ?>) evidence.get("context")).get("clientIp")).isEqualTo("203.0.113.50");

        @SuppressWarnings("unchecked")
        Map<String, Object> consistency = (Map<String, Object>) evidence.get("consistency");
        // consistency 플래그는 어느 링크가 빠졌는지 바로 진단하기 위한 최소 건강검진이다.
        assertThat(consistency)
                .containsEntry("requestRegistered", true)
                .containsEntry("responseCaptured", true)
                .containsEntry("analysisRequestLinked", true)
                .containsEntry("sseLinked", true)
                .containsEntry("contextBindingPresent", true);
    }

    @Test
    @DisplayName("증거 API는 prompt telemetry와 prompt audit 카운터를 함께 노출해야 한다")
    void exposePromptTelemetryFromSaasOutboxPayload() throws Exception {
        ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
        LlmAnalysisEventPublisher publisher = mock(LlmAnalysisEventPublisher.class);
        SecurityDecisionForwardingOutboxRepository decisionOutboxRepository = mock(SecurityDecisionForwardingOutboxRepository.class);
        PromptContextAuditForwardingOutboxRepository promptAuditRepository = mock(PromptContextAuditForwardingOutboxRepository.class);
        com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();

        SecurityTestEvidenceService service = new SecurityTestEvidenceService(
                actionRepository,
                publisher,
                objectMapper,
                providerWith(decisionOutboxRepository),
                providerWith(promptAuditRepository),
                emptyProvider(),
                emptyProvider(),
                emptyProvider(),
                emptyProvider(),
                emptyProvider(),
                emptyProvider()
        );

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-telemetry-001");
        request.addHeader("X-Contexa-Scenario", "ACCOUNT_TAKEOVER");
        request.addHeader("X-Simulated-User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        request.addHeader("X-Forwarded-For", "203.0.113.50");
        request.getSession(true);

        service.registerRequest(request, "alice", "sensitive", "resource-001");

        SecurityDecisionForwardingOutboxRecord decisionOutbox = SecurityDecisionForwardingOutboxRecord.builder()
                .correlationId("req-telemetry-001")
                .tenantExternalRef("default")
                .payloadJson(objectMapper.writeValueAsString(Map.of(
                        "promptVersion", "2026.03.26-e0.1",
                        "promptHash", "sha256:prompt",
                        "systemPromptHash", "sha256:system",
                        "userPromptHash", "sha256:user",
                        "promptEvidenceCompleteness", "SUFFICIENT",
                        "omittedSections", List.of(),
                        "budgetProfile", "CORTEX_L1_STANDARD")))
                .build();
        PromptContextAuditForwardingOutboxRecord promptAuditOutbox = PromptContextAuditForwardingOutboxRecord.builder()
                .auditId("audit-1")
                .correlationId("req-telemetry-001")
                .tenantExternalRef("default")
                .payloadJson(objectMapper.writeValueAsString(Map.of(
                        "retrievalPurpose", "security_investigation",
                        "requestedDocumentCount", 2,
                        "allowedDocumentCount", 2,
                        "deniedDocumentCount", 0,
                        "deniedReasons", List.of())))
                .build();

        when(decisionOutboxRepository.findByCorrelationId("req-telemetry-001")).thenReturn(Optional.of(decisionOutbox));
        when(promptAuditRepository.findByCorrelationId("req-telemetry-001")).thenReturn(Optional.of(promptAuditOutbox));
        when(actionRepository.getAnalysisData("alice")).thenReturn(ZeroTrustAnalysisData.pending());
        when(publisher.getRecentEvents("alice")).thenReturn(List.of());

        Map<String, Object> evidence = service.getEvidence("alice", "req-telemetry-001");

        @SuppressWarnings("unchecked")
        Map<String, Object> prompt = (Map<String, Object>) evidence.get("prompt");
        @SuppressWarnings("unchecked")
        Map<String, Object> telemetry = (Map<String, Object>) prompt.get("telemetry");
        @SuppressWarnings("unchecked")
        Map<String, Object> audit = (Map<String, Object>) prompt.get("audit");

        // 심사와 디버깅에서는 어떤 프롬프트 버전/해시가 어떤 산출물을 만들었는지 바로 보여야 한다.
        assertThat(prompt).containsEntry("present", true);
        assertThat(telemetry)
                .containsEntry("promptVersion", "2026.03.26-e0.1")
                .containsEntry("promptHash", "sha256:prompt")
                .containsEntry("systemPromptHash", "sha256:system")
                .containsEntry("userPromptHash", "sha256:user")
                .containsEntry("promptEvidenceCompleteness", "SUFFICIENT")
                .containsEntry("budgetProfile", "CORTEX_L1_STANDARD");
        // retrievalPurpose와 허용/거부 문서 수는 RAG 경로가 실제로 작동했는지를 설명하는 핵심 근거다.
        assertThat(audit)
                .containsEntry("retrievalPurpose", "security_investigation")
                .containsEntry("requestedDocumentCount", 2)
                .containsEntry("allowedDocumentCount", 2)
                .containsEntry("deniedDocumentCount", 0);
    }

    @SuppressWarnings("unchecked")
    private <T> ObjectProvider<T> emptyProvider() {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return provider;
    }

    @SuppressWarnings("unchecked")
    private <T> ObjectProvider<T> providerWith(T instance) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(instance);
        return provider;
    }
}
