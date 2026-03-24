package io.contexa.contexacommon.bridge;

import io.contexa.bridge_oauth2.controller.ApiController;
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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class BridgeOauth2JwtBridgeIntegrationTest {

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void securityOnPathShouldAbsorbJwtFromSecurityContextAndKeepCustomerControllerWorking() throws Exception {
        ApiController controller = new ApiController();
        BridgeResolutionFilter bridgeResolutionFilter = createBridgeResolutionFilter();

        Jwt jwt = Jwt.withTokenValue("header.payload.signature")
                .header("alg", "RS256")
                .claim("sub", "oauth-security-on")
                .claim("name", "Security On User")
                .claim("organizationId", "tenant-on")
                .claim("department", "risk")
                .claim("roles", List.of("ADMIN"))
                .claim("permissions", List.of("REPORT_EXPORT"))
                .claim("scope", "profile report.read")
                .claim("auth_time", 1711276200L)
                .claim("amr", List.of("pwd", "otp"))
                .build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(
                jwt,
                List.of(new SimpleGrantedAuthority("SCOPE_profile"), new SimpleGrantedAuthority("SCOPE_report.read"))
        ));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/profile");
        MockHttpServletResponse response = new MockHttpServletResponse();
        bridgeResolutionFilter.doFilter(request, response, noOpChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authenticationStamp().principalId()).isEqualTo("oauth-security-on");
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.coverageReport().level()).isEqualTo(BridgeCoverageLevel.AUTHORIZATION_CONTEXT);

        Map<String, Object> payload = controller.profile();
        assertThat(payload.get("username")).isEqualTo("oauth-security-on");
        assertThat((List<String>) payload.get("authorities")).contains("SCOPE_profile", "SCOPE_report.read");
    }

    @Test
    void securityOffPathShouldAbsorbVerifiedRequestObjectAndPromoteAuthenticationForCustomerController() throws Exception {
        ApiController controller = new ApiController();
        BridgeResolutionFilter bridgeResolutionFilter = createBridgeResolutionFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/profile");
        request.setAttribute("verifiedJwtUser", new VerifiedJwtUser(
                "oauth-security-off",
                "Security Off User",
                List.of("ROLE_ADMIN", "REPORT_EXPORT", "SCOPE_profile", "SCOPE_report.read"),
                "JWT",
                "HIGH",
                true,
                Instant.parse("2026-03-24T09:30:00Z"),
                "tenant-off",
                "platform"
        ));
        MockHttpServletResponse response = new MockHttpServletResponse();
        bridgeResolutionFilter.doFilter(request, response, noOpChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authenticationStamp().principalId()).isEqualTo("oauth-security-off");
        assertThat(result.authenticationStamp().authenticationSource()).isEqualTo("REQUEST_ATTRIBUTE");
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.authorizationStamp().decisionSource()).isEqualTo("AUTHENTICATION_DERIVED");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("oauth-security-off");

        Map<String, Object> payload = controller.profile();
        assertThat(payload.get("username")).isEqualTo("oauth-security-off");
        assertThat((List<String>) payload.get("authorities")).contains("ROLE_ADMIN", "REPORT_EXPORT", "SCOPE_profile", "SCOPE_report.read");
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
                                new RequestAttributeAuthBridge(properties.getAuthentication().getRequestAttributes()),
                                new HeaderAuthBridge(properties.getAuthentication().getHeaders())
                        )))
                ),
                List.of(
                        new SecurityContextAuthorizationStampResolver(),
                        new SessionAuthorizationStampResolver(),
                        new HeaderAuthorizationStampResolver()
                ),
                List.of(),
                new BridgeCoverageEvaluator()
        );
    }

    private FilterChain noOpChain() {
        return new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            }
        };
    }

    static class VerifiedJwtUser {
        private final String userId;
        private final String displayName;
        private final List<String> authorities;
        private final String authenticationType;
        private final String authenticationAssurance;
        private final boolean mfa;
        private final Instant authenticationTime;
        private final String organizationId;
        private final String department;

        VerifiedJwtUser(String userId, String displayName, List<String> authorities, String authenticationType, String authenticationAssurance, boolean mfa, Instant authenticationTime, String organizationId, String department) {
            this.userId = userId;
            this.displayName = displayName;
            this.authorities = authorities;
            this.authenticationType = authenticationType;
            this.authenticationAssurance = authenticationAssurance;
            this.mfa = mfa;
            this.authenticationTime = authenticationTime;
            this.organizationId = organizationId;
            this.department = department;
        }

        public String getUserId() { return userId; }
        public String getDisplayName() { return displayName; }
        public List<String> getAuthorities() { return authorities; }
        public String getAuthenticationType() { return authenticationType; }
        public String getAuthenticationAssurance() { return authenticationAssurance; }
        public boolean isMfa() { return mfa; }
        public Instant getAuthenticationTime() { return authenticationTime; }
        public String getOrganizationId() { return organizationId; }
        public String getDepartment() { return department; }
    }
}
