package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgedUser;
import io.contexa.contexacommon.security.bridge.SessionAuthBridge;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SessionAuthBridgeTest {

    private final SessionAuthBridge bridge = new SessionAuthBridge(new BridgeProperties.Session());

    @Test
    void shouldExtractStandardAuthenticationAttributesFromSessionUser() {
        SessionUser sessionUser = new SessionUser();
        sessionUser.setUserId("alice");
        sessionUser.setDisplayName("Alice");
        sessionUser.setRoles(List.of("ROLE_USER", "REPORT_READ"));
        sessionUser.setAuthMethod("PASSKEY");
        sessionUser.setAuthenticationAssurance("HIGH");
        sessionUser.setMfaVerified(true);
        sessionUser.setLoginTime(Instant.parse("2026-03-23T10:15:30Z"));

        MockHttpServletRequestBuilder requestBuilder = new MockHttpServletRequestBuilder();
        requestBuilder.setSessionAttribute("LOGIN_USER", sessionUser);

        BridgedUser bridgedUser = bridge.extractUser(requestBuilder.request());

        assertThat(bridgedUser).isNotNull();
        assertThat(bridgedUser.username()).isEqualTo("alice");
        assertThat(bridgedUser.displayName()).isEqualTo("Alice");
        assertThat(bridgedUser.roles()).containsExactlyInAnyOrder("ROLE_USER", "REPORT_READ");
        assertThat(bridgedUser.attributes())
                .containsEntry("authenticationType", "PASSKEY")
                .containsEntry("authenticationAssurance", "HIGH")
                .containsEntry("mfaCompleted", true)
                .containsEntry("authenticationTime", Instant.parse("2026-03-23T10:15:30Z"));
    }

    private static class SessionUser {
        private String userId;
        private String displayName;
        private List<String> roles = List.of();
        private String authMethod;
        private String authenticationAssurance;
        private boolean mfaVerified;
        private Instant loginTime;

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

        public String getAuthMethod() {
            return authMethod;
        }

        public void setAuthMethod(String authMethod) {
            this.authMethod = authMethod;
        }

        public String getAuthenticationAssurance() {
            return authenticationAssurance;
        }

        public void setAuthenticationAssurance(String authenticationAssurance) {
            this.authenticationAssurance = authenticationAssurance;
        }

        public boolean isMfaVerified() {
            return mfaVerified;
        }

        public void setMfaVerified(boolean mfaVerified) {
            this.mfaVerified = mfaVerified;
        }

        public Instant getLoginTime() {
            return loginTime;
        }

        public void setLoginTime(Instant loginTime) {
            this.loginTime = loginTime;
        }
    }

    private static class MockHttpServletRequestBuilder {
        private final org.springframework.mock.web.MockHttpServletRequest request = new org.springframework.mock.web.MockHttpServletRequest();
        private final org.springframework.mock.web.MockHttpSession session = new org.springframework.mock.web.MockHttpSession();

        void setSessionAttribute(String key, Object value) {
            session.setAttribute(key, value);
            request.setSession(session);
        }

        org.springframework.mock.web.MockHttpServletRequest request() {
            return request;
        }
    }
}
