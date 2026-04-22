package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationToken;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.handoff.ContexaAuthHandoff;
import io.contexa.contexacommon.security.bridge.handoff.DefaultContexaAuthBridgeHandler;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultContexaAuthBridgeHandlerTest {

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldPreserveExistingCustomerAuthenticationDuringExplicitHandoff() {
        Authentication customerAuthentication = new UsernamePasswordAuthenticationToken(
                "spring-user",
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_CUSTOMER")));
        SecurityContextHolder.getContext().setAuthentication(customerAuthentication);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler().handoff(request, response, handoff("customer-123"));

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authenticationStamp().principalId()).isEqualTo("customer-123");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(customerAuthentication);
    }

    @Test
    void shouldPopulateBridgeAuthenticationWhenCustomerAuthenticationIsAbsent() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/legacy/login");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler().handoff(request, response, handoff("legacy-user"));

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authenticationStamp().principalId()).isEqualTo("legacy-user");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isInstanceOf(BridgeAuthenticationToken.class);
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("legacy-user");
    }

    private DefaultContexaAuthBridgeHandler handler() {
        BridgeProperties properties = new BridgeProperties();
        return new DefaultContexaAuthBridgeHandler(
                properties,
                new RequestContextCollector(),
                new BridgeCoverageEvaluator(),
                new BridgeRuntimeSupport(properties, null),
                null);
    }

    private ContexaAuthHandoff handoff(String principalId) {
        return ContexaAuthHandoff.of(
                        principalId,
                        List.of("ROLE_USER"),
                        Map.of("principalId", principalId, "displayName", principalId))
                .withAuthenticationType("HANDOFF")
                .withAuthenticationAssurance("STANDARD")
                .withMfaVerified(false);
    }
}
