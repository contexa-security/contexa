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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPasskeyRegistrationIntent;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPendingSessionMarker;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import io.contexa.contexacommon.enums.StateType;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaPendingAccessControlFilterTest {

    private static final String MFA_SESSION_ID = "mfa-session-id";

    @Mock
    private MfaSessionRepository sessionRepository;

    @Mock
    private AuthResponseWriter responseWriter;

    private MfaFlowUrlRegistry mfaFlowUrlRegistry;
    private MfaPendingAccessControlFilter filter;

    @BeforeEach
    void setUp() {
        AuthContextProperties properties = new AuthContextProperties();
        AuthUrlProvider authUrlProvider = new AuthUrlProvider(properties);
        mfaFlowUrlRegistry = new MfaFlowUrlRegistry(properties);
        mfaFlowUrlRegistry.createAndRegister("mfa", null, null, null);
        filter = new MfaPendingAccessControlFilter(
                authUrlProvider, mfaFlowUrlRegistry, sessionRepository, responseWriter, "/error");

        when(sessionRepository.getSessionId(any(HttpServletRequest.class))).thenReturn(MFA_SESSION_ID);
        when(sessionRepository.existsSession(MFA_SESSION_ID)).thenReturn(true);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    @DisplayName("Sessions without an incomplete MFA")
    class UnmarkedSessions {

        @Test
        @DisplayName("Authenticated request of an unmarked session passes unchanged")
        void unmarkedSessionPasses() throws Exception {
            authenticate();
            MockHttpServletRequest request = browserRequest("/orders");
            request.getSession(true);
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isSameAs(request);
            assertThat(response.getRedirectedUrl()).isNull();
            verifyNoInteractions(responseWriter, sessionRepository);
        }

        @Test
        @DisplayName("Request without an HTTP session passes unchanged")
        void requestWithoutSessionPasses() throws Exception {
            authenticate();
            MockHttpServletRequest request = browserRequest("/orders");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isSameAs(request);
            assertThat(request.getSession(false)).isNull();
            verifyNoInteractions(responseWriter, sessionRepository);
        }
    }

    @Nested
    @DisplayName("Sessions with an incomplete MFA")
    class MarkedSessions {

        @Test
        @DisplayName("Browser request to a protected resource is redirected to the MFA page")
        void browserRequestIsRedirectedToMfaPage() throws Exception {
            authenticate();
            MockHttpServletRequest request = markedBrowserRequest("/orders", "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FOUND);
            assertThat(response.getRedirectedUrl()).isEqualTo("/mfa/select-factor");
            verifyNoInteractions(responseWriter);
        }

        @Test
        @DisplayName("Browser request is redirected to the login page when the MFA session no longer exists")
        void browserRequestIsRedirectedToLoginPageWhenMfaSessionIsGone() throws Exception {
            authenticate();
            when(sessionRepository.getSessionId(any(HttpServletRequest.class))).thenReturn(null);
            MockHttpServletRequest request = markedBrowserRequest("/orders", "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            assertThat(response.getRedirectedUrl()).isEqualTo("/mfa/login");
        }

        @Test
        @DisplayName("API request to a protected resource receives a 401 JSON error")
        void apiRequestReceivesUnauthorizedJson() throws Exception {
            authenticate();
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders/42");
            request.addHeader("Accept", "application/json");
            MfaPendingSessionMarker.mark(request, "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            assertThat(response.getRedirectedUrl()).isNull();

            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> detailsCaptor = ArgumentCaptor.forClass((Class) Map.class);
            verify(responseWriter).writeErrorResponse(
                    eq(response),
                    eq(HttpServletResponse.SC_UNAUTHORIZED),
                    eq(MfaPendingAccessControlFilter.ERROR_CODE),
                    anyString(),
                    eq("/orders/42"),
                    detailsCaptor.capture());
            assertThat(detailsCaptor.getValue())
                    .containsEntry("error", "MFA_REQUIRED")
                    .containsEntry("mfaSessionActive", true)
                    .containsEntry("redirectUrl", "/mfa/select-factor")
                    .containsEntry("mfaUrl", "/mfa/select-factor");
        }

        @Test
        @DisplayName("XHR request without an active MFA session receives the login page as redirect target")
        void xhrRequestWithoutMfaSessionPointsToLoginPage() throws Exception {
            authenticate();
            when(sessionRepository.existsSession(MFA_SESSION_ID)).thenReturn(false);
            MockHttpServletRequest request = markedBrowserRequest("/orders", "mfa");
            request.addHeader("X-Requested-With", "XMLHttpRequest");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, new MockFilterChain());

            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> detailsCaptor = ArgumentCaptor.forClass((Class) Map.class);
            verify(responseWriter).writeErrorResponse(
                    eq(response),
                    eq(HttpServletResponse.SC_UNAUTHORIZED),
                    eq("MFA_REQUIRED"),
                    anyString(),
                    eq("/orders"),
                    detailsCaptor.capture());
            assertThat(detailsCaptor.getValue())
                    .containsEntry("mfaSessionActive", false)
                    .containsEntry("redirectUrl", "/mfa/login")
                    .doesNotContainKey("mfaUrl");
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "/mfa/login",
                "/api/mfa/login",
                "/login",
                "/logout",
                "/mfa/select-factor",
                "/mfa/failure",
                "/mfa/cancel",
                "/mfa/status",
                "/mfa/request-ott-code",
                "/api/mfa/config",
                "/mfa/ott/request-code-ui",
                "/mfa/ott/generate-code",
                "/mfa/challenge/ott",
                "/login/mfa-ott",
                "/mfa/challenge/passkey",
                "/webauthn/authenticate/options",
                "/login/mfa-webauthn",
                "/mfa/challenge/recovery",
                "/login/recovery/verify",
                "/js/contexa-mfa-sdk.js",
                "/contexa/zero-trust/challenge-required",
                "/contexa/css/main.css",
                "/contexa/js/toast.js",
                "/.well-known/webauthn",
                "/favicon.ico",
                "/error"
        })
        @DisplayName("MFA progress requests pass")
        void mfaProgressRequestsPass(String path) throws Exception {
            authenticate();
            MockHttpServletRequest request = markedBrowserRequest(path, "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isSameAs(request);
            assertThat(response.getRedirectedUrl()).isNull();
            verifyNoInteractions(responseWriter);
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "/",
                "/mfa/success",
                "/webauthn/register/credential-id",
                "/js/app.js",
                "/contexa/admin/users",
                "/contexa/zero-trust",
                "/mfa/select-factor/extra"
        })
        @DisplayName("Requests outside the MFA flow are blocked, including the success page")
        void requestsOutsideMfaFlowAreBlocked(String path) throws Exception {
            authenticate();
            MockHttpServletRequest request = markedBrowserRequest(path, "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            assertThat(response.getRedirectedUrl()).isEqualTo("/mfa/select-factor");
        }

        @Test
        @DisplayName("Anonymous request of a marked session passes so that normal authorization applies")
        void anonymousRequestPasses() throws Exception {
            SecurityContextHolder.setContext(new SecurityContextImpl(new AnonymousAuthenticationToken(
                    "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"))));
            MockHttpServletRequest request = markedBrowserRequest("/orders", "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isSameAs(request);
            verifyNoInteractions(responseWriter);
        }

        @Test
        @DisplayName("Request of a marked session without authentication passes so that normal authorization applies")
        void unauthenticatedRequestPasses() throws Exception {
            MockHttpServletRequest request = markedBrowserRequest("/orders", "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isSameAs(request);
        }

        @Test
        @DisplayName("Context path is honored for permitted paths and redirect targets")
        void contextPathIsHonored() throws Exception {
            authenticate();
            MockHttpServletRequest permitted = markedBrowserRequest("/app/mfa/select-factor", "mfa");
            permitted.setContextPath("/app");
            MockFilterChain permittedChain = new MockFilterChain();
            filter.doFilter(permitted, new MockHttpServletResponse(), permittedChain);
            assertThat(permittedChain.getRequest()).isSameAs(permitted);

            MockHttpServletRequest blocked = markedBrowserRequest("/app/orders", "mfa");
            blocked.setContextPath("/app");
            MockHttpServletResponse blockedResponse = new MockHttpServletResponse();
            MockFilterChain blockedChain = new MockFilterChain();
            filter.doFilter(blocked, blockedResponse, blockedChain);
            assertThat(blockedChain.getRequest()).isNull();
            assertThat(blockedResponse.getRedirectedUrl()).isEqualTo("/app/mfa/select-factor");
        }

        @Test
        @DisplayName("URLs of a prefixed MFA flow pass and its MFA page is used as redirect target")
        void prefixedFlowUrlsAreUsed() throws Exception {
            authenticate();
            mfaFlowUrlRegistry.createAndRegister("mfa_admin", null, null, null, "/admin");

            MockHttpServletRequest permitted = markedBrowserRequest("/admin/login/mfa-ott", "mfa_admin");
            MockFilterChain permittedChain = new MockFilterChain();
            filter.doFilter(permitted, new MockHttpServletResponse(), permittedChain);
            assertThat(permittedChain.getRequest()).isSameAs(permitted);

            MockHttpServletRequest blocked = markedBrowserRequest("/admin/dashboard", "mfa_admin");
            MockHttpServletResponse blockedResponse = new MockHttpServletResponse();
            MockFilterChain blockedChain = new MockFilterChain();
            filter.doFilter(blocked, blockedResponse, blockedChain);
            assertThat(blockedChain.getRequest()).isNull();
            assertThat(blockedResponse.getRedirectedUrl()).isEqualTo("/admin/mfa/select-factor");
        }

        @Test
        @DisplayName("Failure to resolve the MFA session state falls back to the login page")
        void mfaSessionLookupFailureFallsBackToLoginPage() throws Exception {
            authenticate();
            when(sessionRepository.getSessionId(any(HttpServletRequest.class)))
                    .thenThrow(new IllegalStateException("repository unavailable"));
            MockHttpServletRequest request = markedBrowserRequest("/orders", "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            assertThat(response.getRedirectedUrl()).isEqualTo("/mfa/login");
            verify(responseWriter, never()).writeErrorResponse(any(), anyInt(), anyString(), anyString(), anyString(), anyMap());
        }
    }

    @Nested
    @DisplayName("Passkey registration while MFA is pending")
    class PasskeyRegistration {

        @ParameterizedTest
        @ValueSource(strings = {"/webauthn/register", "/webauthn/register/options"})
        @DisplayName("Browser request is blocked and redirected to the MFA passkey page that explains the next step")
        void browserRequestIsRedirectedToPasskeyPage(String path) throws Exception {
            authenticate();
            MockHttpServletRequest request = markedBrowserRequest(path, "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FOUND);
            assertThat(response.getRedirectedUrl()).isEqualTo("/mfa/challenge/passkey");
            verifyNoInteractions(responseWriter);
        }

        @Test
        @DisplayName("API registration request receives a 401 with the passkey registration error and the next step")
        void apiRequestReceivesPasskeyRegistrationError() throws Exception {
            authenticate();
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/webauthn/register");
            request.addHeader("Accept", "application/json");
            MfaPendingSessionMarker.mark(request, "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> detailsCaptor = ArgumentCaptor.forClass((Class) Map.class);
            verify(responseWriter).writeErrorResponse(
                    eq(response),
                    eq(HttpServletResponse.SC_UNAUTHORIZED),
                    eq(MfaPendingAccessControlFilter.PASSKEY_REGISTRATION_ERROR_CODE),
                    anyString(),
                    eq("/webauthn/register"),
                    detailsCaptor.capture());
            assertThat(detailsCaptor.getValue())
                    .containsEntry("error", "PASSKEY_REGISTRATION_REQUIRES_MFA")
                    .containsEntry("mfaSessionActive", true)
                    .containsEntry("nextStepUrl", "/mfa/challenge/passkey")
                    .containsEntry("redirectUrl", "/mfa/challenge/passkey");
            assertThat((String) detailsCaptor.getValue().get("message"))
                    .contains("only after multi-factor authentication is completed");
        }

        @Test
        @DisplayName("XHR registration options request without an active MFA session points to the login page")
        void xhrRequestWithoutMfaSessionPointsToLoginPage() throws Exception {
            authenticate();
            when(sessionRepository.existsSession(MFA_SESSION_ID)).thenReturn(false);
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/webauthn/register/options");
            request.addHeader("X-Requested-With", "XMLHttpRequest");
            MfaPendingSessionMarker.mark(request, "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, new MockFilterChain());

            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> detailsCaptor = ArgumentCaptor.forClass((Class) Map.class);
            verify(responseWriter).writeErrorResponse(
                    eq(response),
                    eq(HttpServletResponse.SC_UNAUTHORIZED),
                    eq("PASSKEY_REGISTRATION_REQUIRES_MFA"),
                    anyString(),
                    eq("/webauthn/register/options"),
                    detailsCaptor.capture());
            assertThat(detailsCaptor.getValue())
                    .containsEntry("mfaSessionActive", false)
                    .containsEntry("nextStepUrl", "/mfa/login")
                    .doesNotContainKey("mfaUrl");
        }

        @Test
        @DisplayName("Registration URLs of a prefixed MFA flow lead to the passkey page of that flow")
        void prefixedFlowRegistrationUsesFlowPasskeyPage() throws Exception {
            authenticate();
            mfaFlowUrlRegistry.createAndRegister("mfa_admin", null, null, null, "/admin");
            MockHttpServletRequest request = markedBrowserRequest("/admin/webauthn/register", "mfa_admin");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            assertThat(response.getRedirectedUrl()).isEqualTo("/admin/mfa/challenge/passkey");
        }

        @Test
        @DisplayName("Other blocked requests keep the generic MFA_REQUIRED response")
        void otherBlockedRequestsKeepGenericResponse() throws Exception {
            authenticate();
            MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/webauthn/register/credential-id");
            request.addHeader("Accept", "application/json");
            MfaPendingSessionMarker.mark(request, "mfa");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, new MockFilterChain());

            verify(responseWriter).writeErrorResponse(
                    eq(response),
                    eq(HttpServletResponse.SC_UNAUTHORIZED),
                    eq(MfaPendingAccessControlFilter.ERROR_CODE),
                    anyString(),
                    eq("/webauthn/register/credential-id"),
                    anyMap());
        }

        @ParameterizedTest
        @ValueSource(strings = {"GET /webauthn/register", "POST /webauthn/register/options", "POST /webauthn/register"})
        @DisplayName("A session with only the first factor cannot register a passkey, even after asking to register one")
        void firstFactorAloneCannotRegisterPasskey(String requestLine) throws Exception {
            authenticate();
            String[] parts = requestLine.split(" ");
            MockHttpServletRequest request = new MockHttpServletRequest(parts[0], parts[1]);
            MfaPendingSessionMarker.mark(request, "mfa");
            MfaPasskeyRegistrationIntent.record(request, MFA_SESSION_ID);
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            assertThat(response.getRedirectedUrl()).isEqualTo("/mfa/challenge/passkey");
        }

        @Test
        @DisplayName("Passkey registration passes once MFA is complete")
        void registrationPassesAfterMfaCompletes() throws Exception {
            authenticate();
            MockHttpServletRequest request = markedBrowserRequest("/webauthn/register", "mfa");
            MfaPendingSessionMarker.clear(request);
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, new MockHttpServletResponse(), chain);

            assertThat(chain.getRequest()).isSameAs(request);
        }
    }

    @Nested
    @DisplayName("Sessions of a token state flow with an incomplete MFA")
    class TokenStateSessions {

        @Test
        @DisplayName("Browser request without a session login is redirected to the MFA page")
        void anonymousBrowserRequestIsRedirectedToMfaPage() throws Exception {
            MockHttpServletRequest request = browserRequest("/orders");
            MfaPendingSessionMarker.mark(request, "mfa", StateType.OAUTH2);
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            assertThat(response.getRedirectedUrl()).isEqualTo("/mfa/select-factor");
        }

        @Test
        @DisplayName("API request without a session login receives the MFA_REQUIRED error")
        void anonymousApiRequestReceivesMfaRequired() throws Exception {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders/42");
            request.addHeader("Accept", "application/json");
            MfaPendingSessionMarker.mark(request, "mfa", StateType.OAUTH2);
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(chain.getRequest()).isNull();
            verify(responseWriter).writeErrorResponse(
                    eq(response),
                    eq(HttpServletResponse.SC_UNAUTHORIZED),
                    eq(MfaPendingAccessControlFilter.ERROR_CODE),
                    anyString(),
                    eq("/orders/42"),
                    any());
        }

        @Test
        @DisplayName("MFA progress requests still pass")
        void mfaProgressRequestPasses() throws Exception {
            MockHttpServletRequest request = browserRequest("/mfa/select-factor");
            MfaPendingSessionMarker.mark(request, "mfa", StateType.OAUTH2);
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, new MockHttpServletResponse(), chain);

            assertThat(chain.getRequest()).isSameAs(request);
        }

        @Test
        @DisplayName("A session state flow keeps letting anonymous requests through")
        void sessionStateAnonymousRequestStillPasses() throws Exception {
            MockHttpServletRequest request = browserRequest("/orders");
            MfaPendingSessionMarker.mark(request, "mfa", StateType.SESSION);
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, new MockHttpServletResponse(), chain);

            assertThat(chain.getRequest()).isSameAs(request);
            verifyNoInteractions(responseWriter);
        }
    }

    private void authenticate() {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                "user", null, List.of());
        SecurityContextHolder.setContext(new SecurityContextImpl(authentication));
    }

    private MockHttpServletRequest browserRequest(String requestUri) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
        request.addHeader("Accept", "text/html");
        return request;
    }

    private MockHttpServletRequest markedBrowserRequest(String requestUri, String flowTypeName) {
        MockHttpServletRequest request = browserRequest(requestUri);
        MfaPendingSessionMarker.mark(request, flowTypeName);
        return request;
    }
}
