package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.*;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageLevel;
import io.contexa.contexacommon.security.bridge.resolver.*;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SessionBridgeStructuralDiscoveryTest {

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldDiscoverAuthenticationFromUnknownSessionAttributeName() {
        SessionAuthBridge bridge = new SessionAuthBridge(new BridgeProperties.Session());
        StructuralSessionContext sessionContext = new StructuralSessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setDisplayName("Alice");
        sessionContext.setRoles(Set.of("ROLE_USER", "REPORT_EXPORT"));
        sessionContext.setAuthMethod("FORM");
        sessionContext.setLoginTime(Instant.parse("2026-03-24T01:10:00Z"));
        sessionContext.setDepartment("FINANCE");

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("CLIENT_RUNTIME_CONTEXT", sessionContext);
        request.setSession(session);

        BridgedUser bridgedUser = bridge.extractUser(request);

        assertThat(bridgedUser).isNotNull();
        assertThat(bridgedUser.username()).isEqualTo("alice");
        assertThat(bridgedUser.roles()).contains("ROLE_USER", "REPORT_EXPORT");
        assertThat(bridgedUser.attributes()).containsEntry("bridgeSessionAttribute", "CLIENT_RUNTIME_CONTEXT");
    }

    @Test
    void shouldDiscoverAuthorizationFromUnknownSessionAttributeName() {
        SessionAuthorizationStampResolver resolver = new SessionAuthorizationStampResolver();
        StructuralSessionContext sessionContext = new StructuralSessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setRoles(Set.of("ROLE_USER"));
        sessionContext.setPermissions(Set.of("REPORT_EXPORT"));
        sessionContext.setAuthorizationEffect("ALLOW");
        sessionContext.setPolicyVersion("v1");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/customers/export");
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("CLIENT_RUNTIME_CONTEXT", sessionContext);
        request.setSession(session);

        AuthorizationStamp stamp = resolver.resolve(
                request,
                new RequestContextSnapshot("/api/customers/export", "GET", "127.0.0.1", "JUnit", "session-1", "request-1", "/api/customers/export", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();

        assertThat(stamp.subjectId()).isEqualTo("alice");
        assertThat(stamp.effect()).isEqualTo(AuthorizationEffect.ALLOW);
        assertThat(stamp.effectiveRoles()).contains("ROLE_USER");
        assertThat(stamp.effectiveAuthorities()).contains("REPORT_EXPORT");
        assertThat(stamp.attributes()).containsEntry("bridgeSessionAttribute", "CLIENT_RUNTIME_CONTEXT");
    }

    @Test
    void shouldDiscoverDelegationFromUnknownSessionAttributeName() {
        SessionDelegationStampResolver resolver = new SessionDelegationStampResolver();
        StructuralSessionContext sessionContext = new StructuralSessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setDelegated(true);
        sessionContext.setAgentId("agent-1");
        sessionContext.setObjectiveId("objective-1");
        sessionContext.setAllowedOperations(Set.of("EXPORT"));
        sessionContext.setAllowedResources(Set.of("customer:export"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/customers/export");
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("CLIENT_RUNTIME_CONTEXT", sessionContext);
        request.setSession(session);

        DelegationStamp stamp = resolver.resolve(
                request,
                new RequestContextSnapshot("/api/customers/export", "GET", "127.0.0.1", "JUnit", "session-1", "request-1", "/api/customers/export", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();

        assertThat(stamp.subjectId()).isEqualTo("alice");
        assertThat(stamp.agentId()).isEqualTo("agent-1");
        assertThat(stamp.allowedOperations()).contains("EXPORT");
        assertThat(stamp.attributes()).containsEntry("bridgeSessionAttribute", "CLIENT_RUNTIME_CONTEXT");
    }

    @Test
    void shouldPopulateSecurityContextFromStructurallyDiscoveredSessionContext() throws Exception {
        BridgeProperties properties = new BridgeProperties();
        BridgeResolutionFilter filter = new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(
                        new SecurityContextAuthenticationStampResolver(),
                        new AuthBridgeAuthenticationStampResolver(new CompositeAuthBridge(List.of(new SessionAuthBridge(properties.getAuthentication().getSession()))))
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

        StructuralSessionContext sessionContext = new StructuralSessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setDisplayName("Alice");
        sessionContext.setRoles(Set.of("ROLE_ADMIN"));
        sessionContext.setPermissions(Set.of("CUSTOMER_READ", "CUSTOMER_EXPORT"));
        sessionContext.setAuthorizationEffect("ALLOW");
        sessionContext.setAuthMethod("FORM");

        MockHttpSession session = new MockHttpSession();
        session.setAttribute("CLIENT_RUNTIME_CONTEXT", sessionContext);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/customers/export");
        request.setSession(session);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authenticationStamp().principalId()).isEqualTo("alice");
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.authorizationStamp().effectiveAuthorities()).contains("CUSTOMER_EXPORT");
        assertThat(result.coverageReport().level()).isEqualTo(BridgeCoverageLevel.AUTHORIZATION_CONTEXT);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("alice");
    }

    static class StructuralSessionContext {
        private String userId;
        private String displayName;
        private Set<String> roles = Set.of();
        private Set<String> permissions = Set.of();
        private String authMethod;
        private Instant loginTime;
        private String department;
        private String authorizationEffect;
        private String policyVersion;
        private boolean delegated;
        private String agentId;
        private String objectiveId;
        private Set<String> allowedOperations = Set.of();
        private Set<String> allowedResources = Set.of();

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getDisplayName() { return displayName; }
        public void setDisplayName(String displayName) { this.displayName = displayName; }
        public Set<String> getRoles() { return roles; }
        public void setRoles(Set<String> roles) { this.roles = roles; }
        public Set<String> getPermissions() { return permissions; }
        public void setPermissions(Set<String> permissions) { this.permissions = permissions; }
        public String getAuthMethod() { return authMethod; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }
        public Instant getLoginTime() { return loginTime; }
        public void setLoginTime(Instant loginTime) { this.loginTime = loginTime; }
        public String getDepartment() { return department; }
        public void setDepartment(String department) { this.department = department; }
        public String getAuthorizationEffect() { return authorizationEffect; }
        public void setAuthorizationEffect(String authorizationEffect) { this.authorizationEffect = authorizationEffect; }
        public String getPolicyVersion() { return policyVersion; }
        public void setPolicyVersion(String policyVersion) { this.policyVersion = policyVersion; }
        public boolean isDelegated() { return delegated; }
        public void setDelegated(boolean delegated) { this.delegated = delegated; }
        public String getAgentId() { return agentId; }
        public void setAgentId(String agentId) { this.agentId = agentId; }
        public String getObjectiveId() { return objectiveId; }
        public void setObjectiveId(String objectiveId) { this.objectiveId = objectiveId; }
        public Set<String> getAllowedOperations() { return allowedOperations; }
        public void setAllowedOperations(Set<String> allowedOperations) { this.allowedOperations = allowedOperations; }
        public Set<String> getAllowedResources() { return allowedResources; }
        public void setAllowedResources(Set<String> allowedResources) { this.allowedResources = allowedResources; }
    }
}
