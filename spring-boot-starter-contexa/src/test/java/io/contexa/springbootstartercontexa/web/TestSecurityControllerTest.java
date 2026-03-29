package io.contexa.springbootstartercontexa.web;

import io.contexa.springbootstartercontexa.service.SecurityTestEvidenceService;
import io.contexa.springbootstartercontexa.service.TestSecurityService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TestSecurityControllerTest {

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("즉시 응답은 인증 운반 메타데이터를 서버 truth 기준으로 그대로 노출한다")
    void auth() {
        TestSecurityService testSecurityService = mock(TestSecurityService.class);
        SecurityTestEvidenceService securityTestEvidenceService = mock(SecurityTestEvidenceService.class);
        TestSecurityController controller = new TestSecurityController(testSecurityService, securityTestEvidenceService);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("alice", "pw"));

        when(testSecurityService.getSensitiveData("resource-001")).thenReturn("ok");
        when(securityTestEvidenceService.registerRequest(
                any(MockHttpServletRequest.class),
                eq("alice"),
                eq("sensitive"),
                eq("resource-001")
        )).thenReturn(new SecurityTestEvidenceService.RequestRegistration(
                "req-001",
                "req-001",
                "ACCOUNT_TAKEOVER",
                "CHALLENGE",
                "run-001",
                "INITIAL",
                "203.0.113.50",
                "Android 10 / Hijacked Session",
                "session-001",
                "/api/security-test/sensitive/resource-001",
                "/api/security-test/sensitive/resource-001",
                "header",
                "localStorage",
                "SESSION_COOKIE + BEARER",
                "alice",
                true
        ));

        ResponseEntity<Map<String, Object>> response =
                controller.testSensitiveData("resource-001", new MockHttpServletRequest("GET", "/api/security-test/sensitive/resource-001"));

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody())
                .containsEntry("authMode", "header")
                .containsEntry("tokenSource", "localStorage")
                .containsEntry("authCarrier", "SESSION_COOKIE + BEARER")
                .containsEntry("authSubjectHint", "alice")
                .containsEntry("authorizationHeaderPresent", true)
                .containsEntry("user", "alice");
    }
}
