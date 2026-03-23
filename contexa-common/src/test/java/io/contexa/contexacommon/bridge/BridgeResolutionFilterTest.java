package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.CompositeAuthBridge;
import io.contexa.contexacommon.security.bridge.HeaderAuthBridge;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageLevel;
import io.contexa.contexacommon.security.bridge.resolver.AuthBridgeAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.HeaderAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.HeaderDelegationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class BridgeResolutionFilterTest {

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldResolveBridgeContextFromHeadersAndPopulateSecurityContext() throws Exception {
        BridgeProperties properties = new BridgeProperties();
        BridgeResolutionFilter filter = new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new AuthBridgeAuthenticationStampResolver(new CompositeAuthBridge(List.of(
                        new HeaderAuthBridge(properties.getAuthentication().getHeaders())
                )))),
                List.of(new HeaderAuthorizationStampResolver()),
                List.of(new HeaderDelegationStampResolver()),
                new BridgeCoverageEvaluator()
        );

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/reports/export");
        request.addHeader("X-Contexa-Principal-Id", "alice");
        request.addHeader("X-Contexa-Authorities", "ROLE_USER,REPORT_EXPORT");
        request.addHeader("X-Contexa-Authenticated", "true");
        request.addHeader("X-Contexa-Authentication-Type", "JWT");
        request.addHeader("X-Contexa-Authentication-Assurance", "HIGH");
        request.addHeader("X-Contexa-Mfa-Completed", "true");
        request.addHeader("X-Contexa-Authz-Effect", "ALLOW");
        request.addHeader("X-Contexa-Authz-Roles", "ROLE_USER");
        request.addHeader("X-Contexa-Authz-Authorities", "REPORT_EXPORT");
        request.addHeader("X-Contexa-Authz-Privileged", "true");
        request.addHeader("X-Contexa-Delegated", "true");
        request.addHeader("X-Contexa-Agent-Id", "agent-1");
        request.addHeader("X-Contexa-Objective-Id", "objective-1");
        request.addHeader("X-Contexa-Allowed-Operations", "EXPORT");
        request.addHeader("X-Contexa-Allowed-Resources", "report:monthly");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.coverageReport().level()).isEqualTo(BridgeCoverageLevel.DELEGATION_CONTEXT);
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.delegationStamp()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("alice");
    }
}
