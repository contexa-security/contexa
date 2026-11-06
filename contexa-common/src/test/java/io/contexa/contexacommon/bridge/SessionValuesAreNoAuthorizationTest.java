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

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.resolver.HeaderAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.RequestAttributeAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.SessionAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What an application keeps in the session for its own pages is no authorization: the values of a search form say
 * nothing of what the user may do. The authorization stamp is the evidence a decision reads of the user's roles,
 * authorities, privilege and the application's verdict, so a session value that only looks like one must add nothing
 * to it. Only the attribute the application names as its authorization is read.
 */
class SessionValuesAreNoAuthorizationTest {

    private final BridgeProperties properties = new BridgeProperties();
    private MockHttpSession session;

    @BeforeEach
    void signedIn() {
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                "alice", null, AuthorityUtils.createAuthorityList("ROLE_USER")));
        session = new MockHttpSession();
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    /** The authorization resolvers in the order the auto-configuration registers them. */
    private AuthorizationStamp stamp() throws Exception {
        BridgeResolutionFilter filter = new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()),
                List.of(
                        new SecurityContextAuthorizationStampResolver(),
                        new SessionAuthorizationStampResolver(),
                        new RequestAttributeAuthorizationStampResolver(),
                        new HeaderAuthorizationStampResolver()),
                List.of(),
                new BridgeCoverageEvaluator());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setSession(session);
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authorizationStamp()).isNotNull();
        return result.authorizationStamp();
    }

    @Test
    @DisplayName("without session values the stamp holds the user's own authorities")
    void theUsersOwnAuthorities() throws Exception {
        AuthorizationStamp stamp = stamp();

        assertThat(stamp.effectiveAuthorities()).containsExactly("ROLE_USER");
        assertThat(stamp.effectiveRoles()).containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("a map of request values kept in the session adds no role and no authority")
    void aMapOfRequestValuesAddsNoRole() throws Exception {
        Map<String, String> values = new HashMap<>();
        values.put("q", "laptop");
        values.put("roles", "ROLE_ADMIN");
        values.put("permissions", "USER_DELETE");
        session.setAttribute("lastSearch", values);

        AuthorizationStamp stamp = stamp();

        assertThat(stamp.effectiveRoles()).doesNotContain("ROLE_ADMIN");
        assertThat(stamp.effectiveAuthorities()).doesNotContain("ROLE_ADMIN", "USER_DELETE");
        assertThat(stamp.attributes().get("authorizationEvidenceSources")).asList().doesNotContain("SESSION");
    }

    @Test
    @DisplayName("a map of request values kept in the session states no privilege and no verdict")
    void aMapOfRequestValuesStatesNoPrivilege() throws Exception {
        Map<String, String> values = new HashMap<>();
        values.put("privileged", "true");
        values.put("effect", "ALLOW");
        values.put("policyId", "admin-console");
        session.setAttribute("lastSearch", values);

        AuthorizationStamp stamp = stamp();

        assertThat(stamp.privileged()).isNotEqualTo(Boolean.TRUE);
        assertThat(stamp.effect()).isNotEqualTo(AuthorizationEffect.ALLOW);
        assertThat(stamp.policyId()).isNotEqualTo("admin-console");
    }

    @Test
    @DisplayName("a session value under a name an application often gives its user is not read either")
    void aValueUnderACommonName() throws Exception {
        session.setAttribute("user", new HashMap<>(Map.of("roles", "ROLE_ADMIN")));

        assertThat(stamp().effectiveRoles()).doesNotContain("ROLE_ADMIN");
    }

    @Test
    @DisplayName("the attribute the application names as its authorization is read")
    void theNamedAttribute() throws Exception {
        properties.getAuthorization().getSession().setAttribute("LOGIN_AUTHZ");
        session.setAttribute("LOGIN_AUTHZ", new HashMap<>(Map.of("roles", "ROLE_FINANCE", "effect", "ALLOW")));
        session.setAttribute("lastSearch", new HashMap<>(Map.of("roles", "ROLE_ADMIN")));

        AuthorizationStamp stamp = stamp();

        assertThat(stamp.effectiveRoles()).contains("ROLE_FINANCE").doesNotContain("ROLE_ADMIN");
        assertThat(stamp.attributes().get("authorizationEvidenceSources")).asList().contains("SESSION");
    }

    @Test
    @DisplayName("an application that turns discovery on reads every attribute, as before")
    void discoveryTurnedOn() throws Exception {
        properties.getAuthorization().getSession().setAutoDiscover(true);
        session.setAttribute("lastSearch", new HashMap<>(Map.of("roles", "ROLE_ADMIN")));

        assertThat(stamp().effectiveRoles()).contains("ROLE_ADMIN");
    }
}
