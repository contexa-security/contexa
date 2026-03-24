package io.contexa.contexacommon.bridge;

import io.contexa.bridge_example.legacy.filter.LegacyAuthFilter;
import io.contexa.bridge_example.legacy.service.LegacyUserService;
import io.contexa.contexacommon.security.bridge.*;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageLevel;
import io.contexa.contexacommon.security.bridge.resolver.*;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class BridgeExampleLegacyBridgeIntegrationTest {

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldAbsorbFormLoginSessionWithoutCustomerCustomization() throws Exception {
        LegacyUserService userService = new LegacyUserService();
        LegacyAuthFilter legacyAuthFilter = new LegacyAuthFilter(userService);
        BridgeResolutionFilter bridgeResolutionFilter = createBridgeResolutionFilter();

        MockHttpServletRequest loginRequest = new MockHttpServletRequest("POST", "/legacy/login");
        loginRequest.addParameter("username", "admin");
        loginRequest.addParameter("password", "admin123");
        MockHttpServletResponse loginResponse = new MockHttpServletResponse();

        legacyAuthFilter.doFilter(loginRequest, loginResponse, new MockFilterChain());

        assertThat(loginResponse.getRedirectedUrl()).isEqualTo("/legacy/dashboard");
        MockHttpSession session = (MockHttpSession) loginRequest.getSession(false);
        assertThat(session).isNotNull();
        assertThat(session.getAttribute(LegacyAuthFilter.SESSION_USER_KEY)).isNotNull();

        MockHttpServletRequest protectedRequest = new MockHttpServletRequest("GET", "/api/customers/export");
        protectedRequest.setSession(session);
        MockHttpServletResponse protectedResponse = new MockHttpServletResponse();

        legacyAuthFilter.doFilter(protectedRequest, protectedResponse, chainInvoking(bridgeResolutionFilter));

        BridgeResolutionResult result = (BridgeResolutionResult) protectedRequest.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authenticationStamp().principalId()).isEqualTo("USR001");
        assertThat(result.authenticationStamp().authenticationSource()).isEqualTo("SESSION");
        assertThat(result.authenticationStamp().authenticationType()).isEqualTo("FORM");
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.authorizationStamp().decisionSource()).isEqualTo("SESSION");
        assertThat(result.authorizationStamp().effectiveAuthorities()).contains("ADMIN", "MANAGER");
        assertThat(result.coverageReport().level()).isEqualTo(BridgeCoverageLevel.AUTHORIZATION_CONTEXT);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("USR001");
    }

    @Test
    void shouldAbsorbTokenAuthenticationOnSameRequestWithoutCustomerCustomization() throws Exception {
        LegacyUserService userService = new LegacyUserService();
        LegacyAuthFilter legacyAuthFilter = new LegacyAuthFilter(userService);
        BridgeResolutionFilter bridgeResolutionFilter = createBridgeResolutionFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/customers/export");
        request.addHeader("X-Auth-Token", "tok-admin-a1b2c3d4e5f6");
        MockHttpServletResponse response = new MockHttpServletResponse();

        legacyAuthFilter.doFilter(request, response, chainInvoking(bridgeResolutionFilter));

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authenticationStamp().principalId()).isEqualTo("USR001");
        assertThat(result.authenticationStamp().authenticationType()).isEqualTo("TOKEN");
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.authorizationStamp().effectiveAuthorities()).contains("ADMIN", "MANAGER");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("USR001");
    }

    private BridgeResolutionFilter createBridgeResolutionFilter() {
        BridgeProperties properties = new BridgeProperties();
        return new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(
                        new SecurityContextAuthenticationStampResolver(),
                        new AuthBridgeAuthenticationStampResolver(new CompositeAuthBridge(List.of(
                                new SessionAuthBridge(properties.getAuthentication().getSession()),
                                new HeaderAuthBridge(properties.getAuthentication().getHeaders()),
                                new RequestAttributeAuthBridge(properties.getAuthentication().getRequestAttributes())
                        )))
                ),
                List.of(
                        new SecurityContextAuthorizationStampResolver(),
                        new SessionAuthorizationStampResolver(),
                        new HeaderAuthorizationStampResolver()
                ),
                List.of(
                        new SessionDelegationStampResolver(),
                        new HeaderDelegationStampResolver()
                ),
                new BridgeCoverageEvaluator()
        );
    }

    private FilterChain chainInvoking(BridgeResolutionFilter bridgeResolutionFilter) {
        return new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
                bridgeResolutionFilter.doFilter(request, response, new MockFilterChain());
            }
        };
    }
}
