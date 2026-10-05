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
package io.contexa.contexaidentity.security.core.mfa.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import jakarta.servlet.http.HttpSession;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;

class MfaPendingSessionMarkerTest {

    private final Authentication authentication =
            UsernamePasswordAuthenticationToken.authenticated("user", null, List.of());

    @Test
    @DisplayName("mark creates the session and stores the pending flow type name")
    void markStoresFlowTypeName() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        MfaPendingSessionMarker.mark(request, "mfa_admin");

        assertThat(request.getSession(false)).isNotNull();
        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isEqualTo("mfa_admin");
    }

    @Test
    @DisplayName("mark without flow type name falls back to the base MFA flow")
    void markWithoutFlowTypeNameUsesBaseFlow() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        MfaPendingSessionMarker.mark(request, null);

        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isEqualTo("mfa");
    }

    @Test
    @DisplayName("clear removes the marker and tolerates missing or invalidated sessions")
    void clearRemovesMarker() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingSessionMarker.mark(request, "mfa");

        MfaPendingSessionMarker.clear(request);

        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isNull();
        assertThatCode(() -> MfaPendingSessionMarker.clear(new MockHttpServletRequest())).doesNotThrowAnyException();

        MockHttpServletRequest invalidated = new MockHttpServletRequest();
        MfaPendingSessionMarker.mark(invalidated, "mfa");
        invalidated.getSession(false).invalidate();
        assertThatCode(() -> MfaPendingSessionMarker.clear(invalidated)).doesNotThrowAnyException();
        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(invalidated)).isNull();
    }

    @Test
    @DisplayName("Marker survives session id change on authentication")
    void markerSurvivesChangeSessionId() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingSessionMarker.mark(request, "mfa");
        String originalSessionId = request.getSession(false).getId();

        new ChangeSessionIdAuthenticationStrategy()
                .onAuthentication(authentication, request, new MockHttpServletResponse());

        assertThat(request.getSession(false).getId()).isNotEqualTo(originalSessionId);
        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isEqualTo("mfa");
    }

    @Test
    @DisplayName("Marker survives a new session that migrates only Spring Security attributes")
    void markerSurvivesNewSessionWithoutAttributeMigration() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingSessionMarker.mark(request, "mfa");
        HttpSession originalSession = request.getSession(false);
        originalSession.setAttribute("APPLICATION_ATTRIBUTE", "value");

        SessionFixationProtectionStrategy strategy = new SessionFixationProtectionStrategy();
        strategy.setMigrateSessionAttributes(false);
        strategy.onAuthentication(authentication, request, new MockHttpServletResponse());

        HttpSession newSession = request.getSession(false);
        assertThat(newSession).isNotSameAs(originalSession);
        assertThat(newSession.getAttribute("APPLICATION_ATTRIBUTE")).isNull();
        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isEqualTo("mfa");
    }
}
