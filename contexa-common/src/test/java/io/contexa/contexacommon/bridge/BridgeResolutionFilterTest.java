/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacommon.bridge;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacommon.security.bridge.*;
import io.contexa.contexacommon.security.bridge.authentication.HostPrincipalSnapshot;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageLevel;
import io.contexa.contexacommon.security.bridge.coverage.MissingBridgeContext;
import io.contexa.contexacommon.security.bridge.resolver.*;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

class BridgeResolutionFilterTest {

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldResolveHeaderContextWithoutReplacingHostAuthentication() throws Exception {
        BridgeResolutionFilter filter = createExternalContextFilter();
        Authentication hostAuthentication = authenticateHost("host-user", "ROLE_HOST");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/reports/export");
        populateHeaderBridgeContext(request);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.coverageReport().level()).isEqualTo(BridgeCoverageLevel.DELEGATION_CONTEXT);
        assertThat(result.coverageReport().summary()).contains("Bridge completeness reached authentication, authorization, and delegated execution context");
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.authorizationStamp().subjectId()).isEqualTo("alice");
        assertThat(result.authorizationStamp().policyVersion()).isEqualTo("2026.03");
        assertThat(result.delegationStamp()).isNotNull();
        assertThat(result.delegationStamp().subjectId()).isEqualTo("alice");
        assertThat(result.delegationStamp().expiresAt()).isEqualTo(Instant.parse("2026-03-24T00:00:00Z"));
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(hostAuthentication);
    }

    @Test
    void shouldResolveAuthenticationAuthorizationAndDelegationFromSessionOnly() throws Exception {
        BridgeResolutionFilter filter = createExternalContextFilter();
        Authentication hostAuthentication = authenticateHost("host-user", "ROLE_HOST");

        MockHttpSession session = new MockHttpSession();
        session.setAttribute("LOGIN_USER", sessionUser("alice", List.of("ROLE_USER", "REPORT_EXPORT")));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
        request.setSession(session);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authenticationStamp().authenticationSource()).isEqualTo("SESSION");
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.authorizationStamp().decisionSource()).isEqualTo("SESSION");
        assertThat(result.authorizationStamp().effectiveRoles()).contains("ROLE_USER");
        assertThat(result.authorizationStamp().effectiveAuthorities()).contains("ROLE_USER", "REPORT_EXPORT");
        assertThat(result.delegationStamp()).isNotNull();
        assertThat(result.delegationStamp().agentId()).isEqualTo("agent-1");
        assertThat(result.delegationStamp().objectiveId()).isEqualTo("objective-1");
        assertThat(result.coverageReport().level()).isEqualTo(BridgeCoverageLevel.DELEGATION_CONTEXT);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(hostAuthentication);
    }

    @Test
    void shouldDeriveAuthorizationStampFromAuthenticationAuthoritiesWhenExplicitAuthorizationIsMissing() throws Exception {
        BridgeResolutionFilter filter = createExternalContextFilter();
        Authentication hostAuthentication = authenticateHost("host-user", "ROLE_HOST");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
        request.addHeader("X-Contexa-Principal-Id", "alice");
        request.addHeader("X-Contexa-Authorities", "ROLE_USER,REPORT_EXPORT");
        request.addHeader("X-Contexa-Authenticated", "true");
        request.addHeader("X-Contexa-Authentication-Type", "JWT");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.authorizationStamp().decisionSource()).isEqualTo("AUTHENTICATION_DERIVED");
        assertThat(result.authorizationStamp().effect().name()).isEqualTo("UNKNOWN");
        assertThat(result.authorizationStamp().effectiveRoles()).contains("ROLE_USER");
        assertThat(result.authorizationStamp().effectiveAuthorities()).contains("ROLE_USER", "REPORT_EXPORT");
        assertThat(result.authorizationStamp().privileged()).isNull();
        assertThat(result.authorizationStamp().attributes())
                .containsEntry("authorizationEvidenceState", "DERIVED_RUNTIME_FALLBACK");
        assertThat(result.coverageReport().level()).isEqualTo(BridgeCoverageLevel.AUTHORIZATION_CONTEXT);
        assertThat(result.coverageReport().missingContexts()).contains(MissingBridgeContext.AUTHORIZATION_EFFECT);
        assertThat(result.coverageReport().summary()).contains("Bridge completeness reached authentication");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(hostAuthentication);
    }

    @Test
    void shouldResolveExistingHostAuthenticationWithoutHeaderContract() throws Exception {
        BridgeResolutionFilter filter = createSecurityContextFilter();
        Authentication hostAuthentication = authenticateHost("alice", "ROLE_USER", "REPORT_EXPORT");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
        request.addHeader("User-Agent", "JUnit");
        request.setRemoteAddr("10.0.0.10");
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        var hostSnapshot = (HostPrincipalSnapshot)
                request.getAttribute(BridgeRequestAttributes.HOST_PRINCIPAL_SNAPSHOT);
        assertThat(hostSnapshot.principalId()).isEqualTo("alice");
        assertThat(hostSnapshot.authorities()).containsExactlyInAnyOrder("ROLE_USER", "REPORT_EXPORT");
        assertThat(hostSnapshot.trustedAttributes()).containsEntry("authenticated", true);
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authenticationStamp().principalId()).isEqualTo("alice");
        assertThat(result.authenticationStamp().authenticationType()).isEqualTo("UsernamePasswordAuthenticationToken");
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.authorizationStamp().decisionSource()).isEqualTo("SECURITY_CONTEXT");
        assertThat(result.authorizationStamp().effectiveAuthorities()).contains("REPORT_EXPORT");
        assertThat(result.coverageReport().level()).isEqualTo(BridgeCoverageLevel.AUTHORIZATION_CONTEXT);
        assertThat(result.coverageReport().summary()).contains("Bridge completeness reached authentication");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(hostAuthentication);
    }

    @Test
    void shouldProjectShadowUserSyncResultIntoSecurityContext() throws Exception {
        BridgeProperties properties = new BridgeProperties();
        BridgeResolutionFilter filter = new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new AuthBridgeAuthenticationStampResolver(new CompositeAuthBridge(List.of(
                        new SessionAuthBridge(properties.getAuthentication().getSession()),
                        new HeaderAuthBridge(properties.getAuthentication().getHeaders())
                )))),
                List.of(
                        new SessionAuthorizationStampResolver(),
                        new HeaderAuthorizationStampResolver()
                ),
                List.of(
                        new SessionDelegationStampResolver(),
                        new HeaderDelegationStampResolver()
                ),
                new BridgeCoverageEvaluator(),
                (authenticationStamp, authorizationStamp, requestContext) -> new BridgeUserMirrorSyncResult(
                        77L,
                        "brg_sync_user",
                        authenticationStamp.principalId(),
                        "brg_subject_key",
                        true,
                        true,
                        true,
                        true
                )
        );

        Authentication hostAuthentication = authenticateHost("host-user", "ROLE_HOST");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/reports/export");
        populateHeaderBridgeContext(request);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeUserMirrorSyncResult syncResult =
                (BridgeUserMirrorSyncResult) request.getAttribute(BridgeRequestAttributes.USER_SYNC_RESULT);
        assertThat(syncResult).isNotNull();
        assertThat(syncResult.internalUserId()).isEqualTo(77L);
        assertThat(syncResult.internalUsername()).isEqualTo("brg_sync_user");
        assertThat(syncResult.bridgeSubjectKey()).isEqualTo("brg_subject_key");
        assertThat(syncResult.externalSubjectId()).isEqualTo("alice");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(hostAuthentication);
    }

    private BridgeResolutionFilter createExternalContextFilter() {
        BridgeProperties properties = new BridgeProperties();
        return new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new AuthBridgeAuthenticationStampResolver(new CompositeAuthBridge(List.of(
                        new SessionAuthBridge(properties.getAuthentication().getSession()),
                        new HeaderAuthBridge(properties.getAuthentication().getHeaders())
                )))),
                List.of(
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

    private BridgeResolutionFilter createSecurityContextFilter() {
        BridgeProperties properties = new BridgeProperties();
        return new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()),
                List.of(new SecurityContextAuthorizationStampResolver()),
                List.of(),
                new BridgeCoverageEvaluator()
        );
    }

    private Authentication authenticateHost(String username, String... authorities) {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                username,
                "n/a",
                AuthorityUtils.createAuthorityList(authorities)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return authentication;
    }

    private void populateHeaderBridgeContext(MockHttpServletRequest request) {
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
        request.addHeader("X-Contexa-Authz-Policy-Version", "2026.03");
        request.addHeader("X-Contexa-Delegated", "true");
        request.addHeader("X-Contexa-Agent-Id", "agent-1");
        request.addHeader("X-Contexa-Objective-Id", "objective-1");
        request.addHeader("X-Contexa-Allowed-Operations", "EXPORT");
        request.addHeader("X-Contexa-Allowed-Resources", "report:monthly");
        request.addHeader("X-Contexa-Delegation-Expires-At", "2026-03-24T00:00:00Z");
    }

    private SessionUser sessionUser(String userId, List<String> permissions) {
        SessionUser sessionUser = new SessionUser();
        sessionUser.setUserId(userId);
        sessionUser.setDisplayName("Alice");
        sessionUser.setRoles(List.of("ROLE_USER"));
        sessionUser.setPermissions(permissions);
        sessionUser.setAuthorizationEffect("ALLOW");
        sessionUser.setPrivileged(false);
        sessionUser.setScopeTags(List.of("customer_data"));
        sessionUser.setDelegated(true);
        sessionUser.setAgentId("agent-1");
        sessionUser.setObjectiveId("objective-1");
        sessionUser.setObjectiveSummary("Export monthly report");
        sessionUser.setAllowedOperations(List.of("EXPORT"));
        sessionUser.setAllowedResources(List.of("report:monthly"));
        sessionUser.setApprovalRequired(true);
        sessionUser.setContainmentOnly(false);
        sessionUser.setExpiresAt(Instant.parse("2026-03-24T00:00:00Z"));
        return sessionUser;
    }

    public static class SessionUser {
        private String userId;
        private String displayName;
        private List<String> roles = List.of();
        private List<String> permissions = List.of();
        private List<String> scopeTags = List.of();
        private String authorizationEffect;
        private boolean privileged;
        private boolean delegated;
        private String agentId;
        private String objectiveId;
        private String objectiveSummary;
        private List<String> allowedOperations = List.of();
        private List<String> allowedResources = List.of();
        private boolean approvalRequired;
        private boolean containmentOnly;
        private Instant expiresAt;

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }

        public List<String> getRoles() {
            return roles;
        }

        public void setRoles(List<String> roles) {
            this.roles = roles;
        }

        public List<String> getPermissions() {
            return permissions;
        }

        public void setPermissions(List<String> permissions) {
            this.permissions = permissions;
        }

        public List<String> getScopeTags() {
            return scopeTags;
        }

        public void setScopeTags(List<String> scopeTags) {
            this.scopeTags = scopeTags;
        }

        public String getAuthorizationEffect() {
            return authorizationEffect;
        }

        public void setAuthorizationEffect(String authorizationEffect) {
            this.authorizationEffect = authorizationEffect;
        }

        public boolean isPrivileged() {
            return privileged;
        }

        public void setPrivileged(boolean privileged) {
            this.privileged = privileged;
        }

        public boolean isDelegated() {
            return delegated;
        }

        public void setDelegated(boolean delegated) {
            this.delegated = delegated;
        }

        public String getAgentId() {
            return agentId;
        }

        public void setAgentId(String agentId) {
            this.agentId = agentId;
        }

        public String getObjectiveId() {
            return objectiveId;
        }

        public void setObjectiveId(String objectiveId) {
            this.objectiveId = objectiveId;
        }

        public String getObjectiveSummary() {
            return objectiveSummary;
        }

        public void setObjectiveSummary(String objectiveSummary) {
            this.objectiveSummary = objectiveSummary;
        }

        public List<String> getAllowedOperations() {
            return allowedOperations;
        }

        public void setAllowedOperations(List<String> allowedOperations) {
            this.allowedOperations = allowedOperations;
        }

        public List<String> getAllowedResources() {
            return allowedResources;
        }

        public void setAllowedResources(List<String> allowedResources) {
            this.allowedResources = allowedResources;
        }

        public boolean isApprovalRequired() {
            return approvalRequired;
        }

        public void setApprovalRequired(boolean approvalRequired) {
            this.approvalRequired = approvalRequired;
        }

        public boolean isContainmentOnly() {
            return containmentOnly;
        }

        public void setContainmentOnly(boolean containmentOnly) {
            this.containmentOnly = containmentOnly;
        }

        public Instant getExpiresAt() {
            return expiresAt;
        }

        public void setExpiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
        }
    }
}

