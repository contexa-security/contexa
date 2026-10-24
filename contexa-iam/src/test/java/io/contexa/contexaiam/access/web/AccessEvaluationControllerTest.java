package io.contexa.contexaiam.access.web;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.access.AccessEvaluation;
import io.contexa.contexacore.autonomous.access.AccessEvaluationRequest;
import io.contexa.contexacore.autonomous.access.AccessEvaluationService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * docs/agent B4: the AuthZEN endpoints answer only an authenticated enforcement point holding the configured
 * authority, in the AuthZEN shape (decision and context), with the caller's request identifier.
 */
class AccessEvaluationControllerTest {

    private final AccessEvaluationService evaluations = mock(AccessEvaluationService.class);
    private final SecurityZeroTrustProperties.Authzen settings = new SecurityZeroTrustProperties.Authzen();
    private final AccessEvaluationController controller = new AccessEvaluationController(evaluations, settings);
    private final TestingAuthenticationToken gateway = new TestingAuthenticationToken("gateway-client", "n/a",
            "SCOPE_contexa.authzen");

    @Test
    void onlyAnAuthenticatedEnforcementPointWithTheAuthorityIsAnswered() {
        assertThat(controller.evaluate(body(), null, "r-1").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(controller.evaluate(body(), new AnonymousAuthenticationToken("k", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")), null).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        ResponseEntity<Object> person = controller.evaluate(body(), new TestingAuthenticationToken("alice", "n/a",
                "ROLE_USER"), "r-2");
        assertThat(person.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(person.getHeaders().getFirst(AccessEvaluationController.REQUEST_ID_HEADER)).isEqualTo("r-2");
        verify(evaluations, never()).evaluate(any(), any(), any());
    }

    @Test
    void anEvaluationIsAnsweredInTheAuthzenShapeWithTheRequestIdentifier() {
        when(evaluations.evaluate(any(), eq("gateway-client"), eq("r-3"))).thenReturn(new AccessEvaluation(false,
                ZeroTrustAction.CHALLENGE, 0.64, "Outside the delegated objective", "rq-9", true, null, null));

        ResponseEntity<Object> answer = controller.evaluate(body(), gateway, "r-3");

        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(answer.getHeaders().getFirst(AccessEvaluationController.REQUEST_ID_HEADER)).isEqualTo("r-3");
        @SuppressWarnings("unchecked")
        Map<String, Object> view = (Map<String, Object>) answer.getBody();
        assertThat(view).containsEntry("decision", false);
        @SuppressWarnings("unchecked")
        Map<String, Object> context = (Map<String, Object>) view.get("context");
        assertThat(context).containsEntry("reason_admin", Map.of("401", "Outside the delegated objective"))
                .containsKey("reason_user");
        assertThat(context.get("contexa")).isEqualTo(Map.of("action", "CHALLENGE", "risk_score", 0.64,
                "request_id", "rq-9", "enforced", true));
        ArgumentCaptor<AccessEvaluationRequest> request = ArgumentCaptor.forClass(AccessEvaluationRequest.class);
        verify(evaluations).evaluate(request.capture(), eq("gateway-client"), eq("r-3"));
        assertThat(request.getValue().subject().properties()).containsEntry("delegator_id", "alice");
        assertThat(request.getValue().context()).containsEntry("client_ip", "203.0.113.5");

        assertThat(controller.evaluate(Map.of("subject", Map.of("type", "user")), gateway, null).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void aBatchTakesItsDefaultsStopsByItsSemanticAndAnswersAnInvalidItemClosed() {
        when(evaluations.evaluateOrError(any(), any(), any())).thenReturn(new AccessEvaluation(false,
                ZeroTrustAction.BLOCK, 0.9, null, "rq-1", true, null, null));
        Map<String, Object> batch = Map.of(
                "subject", Map.of("type", "user", "id", "bob"),
                "action", Map.of("name", "can_read"),
                "evaluations", List.of(Map.of("resource", Map.of("type", "document", "id", "d1")),
                        Map.of("context", Map.of("client_ip", "203.0.113.5")),
                        Map.of("resource", Map.of("type", "document", "id", "d3"))));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> all = (List<Map<String, Object>>) ((Map<String, Object>) controller
                .evaluateAll(batch, gateway, null).getBody()).get("evaluations");
        assertThat(all).hasSize(3);
        assertThat(all.get(1)).containsEntry("decision", false);
        assertThat(all.get(1).get("context").toString()).contains("error").contains("400");
        verify(evaluations, times(2)).evaluateOrError(any(), eq("gateway-client"), any());

        Map<String, Object> denyFirst = new LinkedHashMap<>(batch);
        denyFirst.put("options", Map.of("evaluations_semantic", "deny_on_first_deny"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> stopped = (List<Map<String, Object>>) ((Map<String, Object>) controller
                .evaluateAll(denyFirst, gateway, null).getBody()).get("evaluations");
        assertThat(stopped).hasSize(1);

        settings.setMaxEvaluations(2);
        assertThat(controller.evaluateAll(batch, gateway, null).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void theMetadataNamesTheDecisionPointAndItsAbsoluteEndpoints() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.well-known/authzen-configuration");
        request.setScheme("https");
        request.setServerName("pdp.example.com");
        request.setServerPort(443);

        assertThat(controller.metadata(request))
                .containsEntry("policy_decision_point", "https://pdp.example.com")
                .containsEntry("access_evaluation_endpoint",
                        "https://pdp.example.com/contexa/authzen/access/v1/evaluation")
                .containsEntry("access_evaluations_endpoint",
                        "https://pdp.example.com/contexa/authzen/access/v1/evaluations");
        settings.setPolicyDecisionPoint("https://contexa.example.com");
        assertThat(controller.metadata(request)).containsEntry("policy_decision_point", "https://contexa.example.com");
    }

    private static Map<String, Object> body() {
        return Map.of(
                "subject", Map.of("type", "agent", "id", "report-agent", "properties", Map.of("delegator_id", "alice")),
                "action", Map.of("name", "can_read"),
                "resource", Map.of("type", "project", "id", "HX-310"),
                "context", Map.of("client_ip", "203.0.113.5"));
    }
}
