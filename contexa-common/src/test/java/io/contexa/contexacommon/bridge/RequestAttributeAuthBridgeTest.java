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
import io.contexa.contexacommon.security.bridge.BridgedUser;
import io.contexa.contexacommon.security.bridge.RequestAttributeAuthBridge;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RequestAttributeAuthBridgeTest {

    @Test
    void shouldAutoDetectVerifiedAuthenticationObjectFromRequestAttributes() {
        BridgeProperties.RequestAttributes properties = new BridgeProperties.RequestAttributes();
        RequestAttributeAuthBridge bridge = new RequestAttributeAuthBridge(properties);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/profile");
        request.setAttribute("verifiedUser", new VerifiedRequestUser(
                "request-user",
                "Request User",
                List.of("ROLE_MANAGER", "REPORT_READ"),
                "PATTERN",
                "HIGH",
                true,
                Instant.parse("2026-03-24T10:15:30Z")
        ));

        BridgedUser user = bridge.extractUser(request);

        assertThat(user).isNotNull();
        assertThat(user.username()).isEqualTo("request-user");
        assertThat(user.displayName()).isEqualTo("Request User");
        assertThat(user.roles()).contains("ROLE_MANAGER", "REPORT_READ");
        assertThat(user.attributes()).containsEntry("bridgeAuthenticationSource", "REQUEST_ATTRIBUTE");
        assertThat(user.attributes()).containsEntry("bridgeRequestAttribute", "verifiedUser");
        assertThat(user.attributes()).containsEntry("bridgeStructuralMatchPurpose", "STRUCTURAL_DISCOVERY_ONLY");
        assertThat(user.attributes()).containsEntry("authenticationType", "PATTERN");
        assertThat(user.attributes()).containsEntry("authenticationAssurance", "HIGH");
        assertThat(user.attributes()).containsEntry("mfaCompleted", true);
        assertThat(user.attributes()).containsEntry("authenticationAssuranceEvidenceState", "EXPLICIT_CUSTOMER_SIGNAL");
    }

    @Test
    void shouldPreferConfiguredRequestAttributeAndTypeHint() {
        BridgeProperties.RequestAttributes properties = new BridgeProperties.RequestAttributes();
        properties.setAttribute("handoffUser");
        properties.setObjectTypeName(HintedRequestUser.class.getName());
        RequestAttributeAuthBridge bridge = new RequestAttributeAuthBridge(properties);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/profile");
        request.setAttribute("candidateUser", new CandidateRequestUser("candidate-user"));
        request.setAttribute("handoffUser", new HintedRequestUser("hint-user"));

        BridgedUser user = bridge.extractUser(request);

        assertThat(user).isNotNull();
        assertThat(user.username()).isEqualTo("hint-user");
        assertThat(user.attributes()).containsEntry("bridgeRequestAttribute", "handoffUser");
    }

    static class VerifiedRequestUser {
        private final String userId;
        private final String displayName;
        private final List<String> authorities;
        private final String authenticationType;
        private final String authenticationAssurance;
        private final boolean mfa;
        private final Instant authenticationTime;

        VerifiedRequestUser(String userId, String displayName, List<String> authorities, String authenticationType, String authenticationAssurance, boolean mfa, Instant authenticationTime) {
            this.userId = userId;
            this.displayName = displayName;
            this.authorities = authorities;
            this.authenticationType = authenticationType;
            this.authenticationAssurance = authenticationAssurance;
            this.mfa = mfa;
            this.authenticationTime = authenticationTime;
        }

        public String getUserId() { return userId; }
        public String getDisplayName() { return displayName; }
        public List<String> getAuthorities() { return authorities; }
        public String getAuthenticationType() { return authenticationType; }
        public String getAuthenticationAssurance() { return authenticationAssurance; }
        public boolean isMfa() { return mfa; }
        public Instant getAuthenticationTime() { return authenticationTime; }
    }

    static class CandidateRequestUser {
        private final String userId;
        CandidateRequestUser(String userId) { this.userId = userId; }
        public String getUserId() { return userId; }
    }

    static class HintedRequestUser {
        private final String userId;
        HintedRequestUser(String userId) { this.userId = userId; }
        public String getUserId() { return userId; }
    }
}
