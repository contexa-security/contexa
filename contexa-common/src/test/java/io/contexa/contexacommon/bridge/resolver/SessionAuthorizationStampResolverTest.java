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
package io.contexa.contexacommon.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.resolver.SessionAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SessionAuthorizationStampResolverTest {

    private final SessionAuthorizationStampResolver resolver = new SessionAuthorizationStampResolver();

    @Test
    void shouldExtractAuthorizationContextFromSessionObject() {
        SessionAuthorization sessionAuthorization = new SessionAuthorization();
        sessionAuthorization.setUserId("alice");
        sessionAuthorization.setRoles(List.of("ROLE_USER", "ROLE_FINANCE"));
        sessionAuthorization.setPermissions(List.of("REPORT_EXPORT", "REPORT_APPROVE"));
        sessionAuthorization.setScopeTags(List.of("customer_data", "export"));
        sessionAuthorization.setPrivileged(true);
        sessionAuthorization.setAuthorizationEffect("ALLOW");
        sessionAuthorization.setPolicyId("policy-1");
        sessionAuthorization.setPolicyVersion("v2");

        MockHttpSession session = new MockHttpSession();
        session.setAttribute("LOGIN_USER", sessionAuthorization);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/reports/export");
        request.setSession(session);

        AuthorizationStamp stamp = resolver.resolve(
                request,
                new RequestContextSnapshot("/reports/export", "POST", "10.0.0.10", "JUnit", "session-1", "request-1", "/reports/export", null, false, Instant.now()),
                new BridgeProperties()
        ).orElseThrow();

        assertThat(stamp.subjectId()).isEqualTo("alice");
        assertThat(stamp.effect()).isEqualTo(AuthorizationEffect.ALLOW);
        assertThat(stamp.privileged()).isTrue();
        assertThat(stamp.policyId()).isEqualTo("policy-1");
        assertThat(stamp.policyVersion()).isEqualTo("v2");
        assertThat(stamp.scopeTags()).contains("customer_data", "export");
        assertThat(stamp.effectiveRoles()).contains("ROLE_USER", "ROLE_FINANCE");
        assertThat(stamp.effectiveAuthorities()).contains("REPORT_EXPORT", "REPORT_APPROVE");
        assertThat(stamp.decisionSource()).isEqualTo("SESSION");
    }

    public static class SessionAuthorization {
        private String userId;
        private List<String> roles = List.of();
        private List<String> permissions = List.of();
        private List<String> scopeTags = List.of();
        private boolean privileged;
        private String authorizationEffect;
        private String policyId;
        private String policyVersion;

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
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

        public boolean isPrivileged() {
            return privileged;
        }

        public void setPrivileged(boolean privileged) {
            this.privileged = privileged;
        }

        public String getAuthorizationEffect() {
            return authorizationEffect;
        }

        public void setAuthorizationEffect(String authorizationEffect) {
            this.authorizationEffect = authorizationEffect;
        }

        public String getPolicyId() {
            return policyId;
        }

        public void setPolicyId(String policyId) {
            this.policyId = policyId;
        }

        public String getPolicyVersion() {
            return policyVersion;
        }

        public void setPolicyVersion(String policyVersion) {
            this.policyVersion = policyVersion;
        }
    }
}

