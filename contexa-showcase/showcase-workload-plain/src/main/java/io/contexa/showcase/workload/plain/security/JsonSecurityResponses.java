package io.contexa.showcase.workload.plain.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.workload.plain.rules.RuleDecision;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JSON answers of a plain control: 401 without a session, 403 with the control, the deciding rule and its reason.
 * The orchestrator reads the body as the "HTTP response" link of the evidence chain (deck p.24).
 */
public class JsonSecurityResponses implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final String control;
    private final ObjectMapper json;

    public JsonSecurityResponses(String control, ObjectMapper json) {
        this.control = control;
        this.json = json;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        write(response, HttpServletResponse.SC_UNAUTHORIZED, Map.of("error", "AUTHENTICATION_REQUIRED", "control", control));
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "ACCESS_DENIED");
        body.put("control", control);
        if (request.getAttribute(ControlAuthorizationManager.DENIAL_ATTRIBUTE) instanceof RuleDecision decision) {
            body.put("rule", decision.ruleId());
            body.put("reason", decision.reason());
        }
        write(response, HttpServletResponse.SC_FORBIDDEN, body);
    }

    private void write(HttpServletResponse response, int status, Map<String, ?> body) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        json.writeValue(response.getOutputStream(), body);
    }
}
