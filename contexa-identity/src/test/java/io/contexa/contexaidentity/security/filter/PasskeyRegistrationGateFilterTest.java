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
package io.contexa.contexaidentity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.execution.ZeroTrustChallengeFlowStarter;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPasskeyRegistrationIntent;
import io.contexa.contexaidentity.security.handler.login.LoginFactsDetails;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import io.contexa.contexaidentity.security.zerotrust.PasskeyRegistrationGate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Q-13 (PR-60): a session under a CHALLENGE, or one that never verified, does not begin a passkey. */
class PasskeyRegistrationGateFilterTest {

    private static final String OPTIONS = "/webauthn/register/options";
    private static final String MFA_PAGE = "/mfa/select-factor";

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final AuthUrlProvider urls = mock(AuthUrlProvider.class);
    private final MfaFlowUrlRegistry registry = mock(MfaFlowUrlRegistry.class);
    private final MfaSessionRepository sessions = mock(MfaSessionRepository.class);
    private final ZeroTrustChallengeFlowStarter starter = mock(ZeroTrustChallengeFlowStarter.class);
    private boolean enforcing = true;
    private boolean verificationAvailable = true;
    private MfaPendingAccessControlFilter filter;

    @BeforeEach
    void setUp() {
        when(urls.getPasskeyRegistrationUrls()).thenReturn(Set.of("/webauthn/register", OPTIONS));
        when(urls.getMfaInProgressUrls()).thenReturn(Set.of());
        when(registry.getAllMfaInProgressUrls()).thenReturn(Set.of());
        when(registry.getAllPasskeyRegistrationUrls()).thenReturn(Set.of());
        when(starter.start(any(), any())).thenReturn(Optional.of(MFA_PAGE));
        when(sessions.getSessionId(any())).thenReturn("flow-1");
        filter = new MfaPendingAccessControlFilter(urls, registry, sessions, new JsonAuthResponseWriter(new ObjectMapper().findAndRegisterModules()), "/error");
        filter.setPasskeyRegistrationGate(
                new PasskeyRegistrationGate(actions, () -> enforcing, () -> verificationAvailable), () -> starter);
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private void signedIn(boolean mfaCompleted) {
        TestingAuthenticationToken authentication = new TestingAuthenticationToken("alice", null, "ROLE_USER");
        authentication.setDetails(new LoginFactsDetails("198.51.100.1", "session-1",
                mfaCompleted ? List.of("password", "otp") : List.of("password"), Instant.now()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private static MockHttpServletRequest post(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        request.addHeader("Accept", "application/json");
        return request;
    }

    private boolean reachedTheChain(MockHttpServletRequest request, MockHttpServletResponse response) throws Exception {
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, response, chain);
        return chain.getRequest() != null;
    }

    @Test
    @DisplayName("a session under a CHALLENGE answers it first: no options, the MFA page instead")
    void underAChallenge() throws Exception {
        signedIn(true);
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(reachedTheChain(post(OPTIONS), response)).isFalse();

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains(MfaPendingAccessControlFilter.PASSKEY_VERIFICATION_ERROR_CODE)
                .contains(MFA_PAGE).doesNotContain("challenge\":\"");
    }

    @Test
    @DisplayName("a session that signed in with the first factor only verifies first, and is brought back")
    void aFirstFactorSession() throws Exception {
        signedIn(false);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/webauthn/register");
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(reachedTheChain(request, response)).isFalse();

        assertThat(response.getRedirectedUrl()).isEqualTo(MFA_PAGE);
        assertThat(MfaPasskeyRegistrationIntent.consume(request, "flow-1")).isTrue();
    }

    @Test
    @DisplayName("a session that completed MFA registers")
    void aVerifiedSession() throws Exception {
        signedIn(true);

        assertThat(reachedTheChain(post(OPTIONS), new MockHttpServletResponse())).isTrue();

        verify(starter, never()).start(any(), any());
    }

    @Test
    @DisplayName("a BLOCK refuses it and starts nothing")
    void underABlock() throws Exception {
        signedIn(true);
        actions.setBlockedFlag("alice");
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(reachedTheChain(post(OPTIONS), response)).isFalse();

        assertThat(response.getStatus()).isEqualTo(403);
        verify(starter, never()).start(any(), any());
    }

    @Test
    @DisplayName("removing a passkey is held to the same rule")
    void removingAPasskey() throws Exception {
        signedIn(false);
        MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/webauthn/register/credential-1");

        assertThat(reachedTheChain(request, new MockHttpServletResponse())).isFalse();
    }

    @Test
    @DisplayName("with no way to start a verification the request is refused, never let through")
    void noFlowCanStart() throws Exception {
        signedIn(false);
        when(starter.start(any(), any())).thenReturn(Optional.empty());
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(reachedTheChain(post(OPTIONS), response)).isFalse();

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    @DisplayName("an application without an MFA flow keeps its passkeys: nothing can be asked, and none answers a CHALLENGE")
    void noMfaFlow() throws Exception {
        verificationAvailable = false;
        signedIn(false);

        assertThat(reachedTheChain(post(OPTIONS), new MockHttpServletResponse())).isTrue();
    }

    @Test
    @DisplayName("under a report-only mode a stored CHALLENGE stops nothing, and the proof is still asked for")
    void reportOnly() throws Exception {
        enforcing = false;
        signedIn(true);
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());

        assertThat(reachedTheChain(post(OPTIONS), new MockHttpServletResponse())).isTrue();

        signedIn(false);
        assertThat(reachedTheChain(post(OPTIONS), new MockHttpServletResponse())).isFalse();
    }

    @Test
    @DisplayName("a visitor is left to Spring Security, and other paths are not looked at")
    void aVisitorAndOtherPaths() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        assertThat(reachedTheChain(post(OPTIONS), new MockHttpServletResponse())).isTrue();

        signedIn(false);
        assertThat(reachedTheChain(post("/orders"), new MockHttpServletResponse())).isTrue();
    }
}
