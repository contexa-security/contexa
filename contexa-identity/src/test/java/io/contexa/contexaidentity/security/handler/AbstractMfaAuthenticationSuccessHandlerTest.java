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
package io.contexa.contexaidentity.security.handler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.springframework.mock.web.MockHttpSession;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPasskeyRegistrationIntent;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPendingSessionMarker;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import io.contexa.contexaidentity.security.handler.login.LoginFactsDetails;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.http.ResponseCookie;
import java.util.List;
import static org.mockito.ArgumentMatchers.any;


class AbstractMfaAuthenticationSuccessHandlerTest {

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("SESSION MFA completion persists final authentication in AISessionSecurityContextRepository")
    void save() throws Exception {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(StateType.SESSION);

        AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
        MfaSessionRepository sessionRepository = mock(MfaSessionRepository.class);
        MfaStateMachineIntegrator integrator = mock(MfaStateMachineIntegrator.class);
        ZeroTrustEventPublisher eventPublisher = mock(ZeroTrustEventPublisher.class);
        ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
        SecurityLearningService learningService = mock(SecurityLearningService.class);
        AuthUrlProvider authUrlProvider = mock(AuthUrlProvider.class);
        MfaFlowUrlRegistry flowUrlRegistry = mock(MfaFlowUrlRegistry.class);
        IBlockedUserRecorder blockedUserRecorder = mock(IBlockedUserRecorder.class);
        BlockMfaStateStore blockMfaStateStore = mock(BlockMfaStateStore.class);
        CentralAuditFacade centralAuditFacade = mock(CentralAuditFacade.class);
        BlockingSignalBroadcaster blockingSignalBroadcaster = mock(BlockingSignalBroadcaster.class);
        AISessionSecurityContextRepository aiRepository = mock(AISessionSecurityContextRepository.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AISessionSecurityContextRepository> provider = mock(ObjectProvider.class);
        ApplicationContext applicationContext = mock(ApplicationContext.class);

        when(applicationContext.getBeanProvider(AISessionSecurityContextRepository.class)).thenReturn(provider);
        when(provider.getIfAvailable()).thenReturn(aiRepository);

        TestHandler handler = new TestHandler(
                null,
                responseWriter,
                sessionRepository,
                integrator,
                properties,
                eventPublisher,
                actionRepository,
                learningService,
                applicationContext,
                authUrlProvider,
                flowUrlRegistry,
                blockedUserRecorder,
                blockMfaStateStore,
                centralAuditFacade,
                blockingSignalBroadcaster,
                false
        );

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/admin/login/mfa-ott");
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN");

        handler.complete(request, response, authentication);

        ArgumentCaptor<SecurityContext> contextCaptor = ArgumentCaptor.forClass(SecurityContext.class);
        verify(aiRepository).saveContext(contextCaptor.capture(), eq(request), eq(response));
        assertThat(contextCaptor.getValue().getAuthentication().getName()).isEqualTo("admin");
    }

    @Test
    @DisplayName("Returns structured error response when post-success pipeline fails")
    void returnsStructuredErrorResponseWhenPostSuccessPipelineFails() throws Exception {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(StateType.SESSION);

        AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
        MfaSessionRepository sessionRepository = mock(MfaSessionRepository.class);
        MfaStateMachineIntegrator integrator = mock(MfaStateMachineIntegrator.class);
        ZeroTrustEventPublisher eventPublisher = mock(ZeroTrustEventPublisher.class);
        ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
        SecurityLearningService learningService = mock(SecurityLearningService.class);
        AuthUrlProvider authUrlProvider = mock(AuthUrlProvider.class);
        MfaFlowUrlRegistry flowUrlRegistry = mock(MfaFlowUrlRegistry.class);
        IBlockedUserRecorder blockedUserRecorder = mock(IBlockedUserRecorder.class);
        BlockMfaStateStore blockMfaStateStore = mock(BlockMfaStateStore.class);
        CentralAuditFacade centralAuditFacade = mock(CentralAuditFacade.class);
        BlockingSignalBroadcaster blockingSignalBroadcaster = mock(BlockingSignalBroadcaster.class);
        AISessionSecurityContextRepository aiRepository = mock(AISessionSecurityContextRepository.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AISessionSecurityContextRepository> provider = mock(ObjectProvider.class);
        ApplicationContext applicationContext = mock(ApplicationContext.class);

        when(applicationContext.getBeanProvider(AISessionSecurityContextRepository.class)).thenReturn(provider);
        when(provider.getIfAvailable()).thenReturn(aiRepository);

        TestHandler handler = new TestHandler(
                null,
                responseWriter,
                sessionRepository,
                integrator,
                properties,
                eventPublisher,
                actionRepository,
                learningService,
                applicationContext,
                authUrlProvider,
                flowUrlRegistry,
                blockedUserRecorder,
                blockMfaStateStore,
                centralAuditFacade,
                blockingSignalBroadcaster,
                true
        );

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/admin/login/mfa-ott");
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN");

        handler.complete(request, response, authentication);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> detailCaptor = ArgumentCaptor.forClass((Class) Map.class);
        verify(responseWriter).writeErrorResponse(
                eq(response),
                eq(HttpServletResponse.SC_INTERNAL_SERVER_ERROR),
                eq("MFA_POST_SUCCESS_PIPELINE_FAILED"),
                contains("buildResponseData"),
                eq("/contexa/admin/login/mfa-ott"),
                detailCaptor.capture());
        assertThat(detailCaptor.getValue())
                .containsEntry("status", "MFA_POST_SUCCESS_PIPELINE_FAILED")
                .containsEntry("failedStage", "buildResponseData")
                .containsEntry("userId", "admin");
    }

    @Test
    @DisplayName("SESSION MFA completion removes the MFA pending marker")
    void sessionCompletionClearsMfaPendingMarker() throws Exception {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(StateType.SESSION);
        TestHandler handler = newHandler(properties, null);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/mfa-ott");
        request.addHeader("Accept", "application/json");
        MfaPendingSessionMarker.mark(request, "mfa");

        handler.complete(request, new MockHttpServletResponse(),
                new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN"));

        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isNull();
    }

    @Test
    @DisplayName("OAUTH2 MFA completion removes the MFA pending marker after the tokens are issued")
    void oauth2CompletionClearsMfaPendingMarkerAfterTokenIssuance() throws Exception {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(StateType.OAUTH2);
        TokenService tokenService = mock(TokenService.class);
        TestHandler handler = newHandler(properties, tokenService);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/login/mfa-ott");
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN");
        MfaPendingSessionMarker.mark(request, "mfa");

        AtomicReference<String> markerAtIssuance = new AtomicReference<>();
        when(tokenService.createTokenPair(eq(authentication), isNull(), eq(request), eq(response)))
                .thenAnswer(invocation -> {
                    markerAtIssuance.set(MfaPendingSessionMarker.getPendingFlowTypeName(request));
                    return TokenPair.builder().accessToken("access").refreshToken("refresh").build();
                });
        when(tokenService.prepareTokensForTransport("access", "refresh"))
                .thenReturn(TokenTransportResult.builder().body(Map.of("accessToken", "access")).build());

        handler.complete(request, response, authentication);

        assertThat(markerAtIssuance.get()).isEqualTo("mfa");
        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isNull();
    }

    @Test
    @DisplayName("Token issuance failure keeps the MFA pending marker")
    void tokenIssuanceFailureKeepsMfaPendingMarker() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(StateType.OAUTH2);
        TokenService tokenService = mock(TokenService.class);
        TestHandler handler = newHandler(properties, tokenService);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/login/mfa-ott");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN");
        MfaPendingSessionMarker.mark(request, "mfa");
        when(tokenService.createTokenPair(eq(authentication), isNull(), eq(request), eq(response)))
                .thenThrow(new IllegalStateException("token endpoint unavailable"));

        assertThatThrownBy(() -> handler.complete(request, response, authentication))
                .isInstanceOf(IllegalStateException.class);
        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isEqualTo("mfa");
    }

    @Nested
    @DisplayName("Passkey registration after MFA")
    class PasskeyRegistrationAfterMfa {

        private static final String MFA_SESSION_ID = "mfa-session-id";

        private final AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);

        @Test
        @DisplayName("Browser completion with a recorded intent redirects to passkey registration and consumes the intent")
        void browserCompletionRedirectsToPasskeyRegistration() throws Exception {
            TestHandler handler = sessionHandler();
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/mfa-ott");
            request.addHeader("Accept", "text/html");
            MfaPasskeyRegistrationIntent.record(request, MFA_SESSION_ID);
            MockHttpServletResponse response = new MockHttpServletResponse();

            handler.complete(request, response, authentication(), factorContext());

            assertThat(response.getRedirectedUrl()).isEqualTo("/webauthn/register");
            assertThat(request.getSession(false).getAttribute(MfaPasskeyRegistrationIntent.SESSION_ATTRIBUTE)).isNull();
            assertThat(MfaPasskeyRegistrationIntent.getReturnUrl(request)).isEqualTo("/admin");
        }

        @Test
        @DisplayName("JSON completion with a recorded intent returns passkey registration as redirect URL")
        void jsonCompletionReturnsPasskeyRegistrationUrl() throws Exception {
            TestHandler handler = sessionHandler();
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/app/login/mfa-ott");
            request.setContextPath("/app");
            request.addHeader("Accept", "application/json");
            MfaPasskeyRegistrationIntent.record(request, MFA_SESSION_ID);
            MockHttpServletResponse response = new MockHttpServletResponse();

            handler.complete(request, response, authentication(), factorContext());

            assertThat(response.getRedirectedUrl()).isNull();
            assertThat(writtenBody(response))
                    .containsEntry("status", "MFA_COMPLETED")
                    .containsEntry("redirectUrl", "/app/webauthn/register");
            assertThat(MfaPasskeyRegistrationIntent.consume(request, MFA_SESSION_ID)).isFalse();
            assertThat(MfaPasskeyRegistrationIntent.getReturnUrl(request)).isEqualTo("/admin");
        }

        @Test
        @DisplayName("OAUTH2 completion with a recorded intent returns passkey registration as redirect URL")
        void oauth2CompletionReturnsPasskeyRegistrationUrl() throws Exception {
            AuthContextProperties properties = new AuthContextProperties();
            properties.setStateType(StateType.OAUTH2);
            TokenService tokenService = mock(TokenService.class);
            TestHandler handler = newHandler(properties, tokenService, responseWriter, new AuthUrlProvider(properties));
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/login/mfa-ott");
            request.addHeader("Accept", "application/json");
            MockHttpServletResponse response = new MockHttpServletResponse();
            Authentication authentication = authentication();
            MfaPasskeyRegistrationIntent.record(request, MFA_SESSION_ID);
            when(tokenService.createTokenPair(eq(authentication), isNull(), eq(request), eq(response)))
                    .thenReturn(TokenPair.builder().accessToken("access").refreshToken("refresh").build());
            when(tokenService.prepareTokensForTransport("access", "refresh"))
                    .thenReturn(TokenTransportResult.builder().body(Map.of("accessToken", "access")).build());

            handler.complete(request, response, authentication, factorContext());

            assertThat(writtenBody(response))
                    .containsEntry("accessToken", "access")
                    .containsEntry("redirectUrl", "/webauthn/register");
        }

        @Test
        @DisplayName("OAUTH2 JSON completion with a recorded intent tells a SPA to open passkey registration")
        void oauth2JsonCompletionAnnouncesPasskeyRegistration() throws Exception {
            AuthContextProperties properties = new AuthContextProperties();
            properties.setStateType(StateType.OAUTH2);
            TokenService tokenService = mock(TokenService.class);
            TestHandler handler = newHandler(properties, tokenService, responseWriter, new AuthUrlProvider(properties));
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/mfa-ott");
            request.addHeader("Accept", "application/json");
            MockHttpServletResponse response = new MockHttpServletResponse();
            Authentication authentication = authentication();
            MfaPasskeyRegistrationIntent.record(request, MFA_SESSION_ID);
            when(tokenService.createTokenPair(eq(authentication), isNull(), eq(request), eq(response)))
                    .thenReturn(TokenPair.builder().accessToken("access").refreshToken("refresh").build());
            when(tokenService.prepareTokensForTransport("access", "refresh"))
                    .thenReturn(TokenTransportResult.builder().body(Map.of("tokenTransportMethod", "COOKIE")).build());

            handler.complete(request, response, authentication, factorContext());

            assertThat(writtenBody(response))
                    .containsEntry("nextAction", AbstractMfaAuthenticationSuccessHandler.NEXT_ACTION_PASSKEY_REGISTRATION)
                    .containsEntry("redirectUrl", "/webauthn/register");
        }

        @Test
        @DisplayName("OAUTH2 completion of a plain form submission sets the token cookies and redirects")
        void oauth2FormCompletionRedirectsWithCookies() throws Exception {
            AuthContextProperties properties = new AuthContextProperties();
            properties.setStateType(StateType.OAUTH2);
            TokenService tokenService = mock(TokenService.class);
            TestHandler handler = newHandler(properties, tokenService, responseWriter, new AuthUrlProvider(properties));
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/mfa-ott");
            request.addHeader("Accept", "text/html");
            MockHttpServletResponse response = new MockHttpServletResponse();
            Authentication authentication = authentication();
            MfaPasskeyRegistrationIntent.record(request, MFA_SESSION_ID);
            when(tokenService.createTokenPair(eq(authentication), isNull(), eq(request), eq(response)))
                    .thenReturn(TokenPair.builder().accessToken("access").refreshToken("refresh").build());
            when(tokenService.prepareTokensForTransport("access", "refresh"))
                    .thenReturn(TokenTransportResult.builder()
                            .cookiesToSet(List.of(ResponseCookie.from("accessToken", "access").path("/").build()))
                            .body(Map.of("tokenTransportMethod", "COOKIE"))
                            .build());

            handler.complete(request, response, authentication, factorContext());

            assertThat(response.getRedirectedUrl()).isEqualTo("/webauthn/register");
            assertThat(response.getHeaders("Set-Cookie")).anyMatch(c -> c.startsWith("accessToken=access"));
            verify(responseWriter, never()).writeSuccessResponse(any(), any(), anyInt());
        }

        @Test
        @DisplayName("Completion without an intent keeps the regular target")
        void completionWithoutIntentKeepsRegularTarget() throws Exception {
            TestHandler handler = sessionHandler();
            MockHttpServletRequest browser = new MockHttpServletRequest("POST", "/login/mfa-ott");
            browser.addHeader("Accept", "text/html");
            MockHttpServletResponse browserResponse = new MockHttpServletResponse();

            handler.complete(browser, browserResponse, authentication(), factorContext());

            assertThat(browserResponse.getRedirectedUrl()).isEqualTo("/admin");
            assertThat(MfaPasskeyRegistrationIntent.getReturnUrl(browser)).isNull();

            MockHttpServletRequest json = new MockHttpServletRequest("POST", "/login/mfa-ott");
            json.addHeader("Accept", "application/json");
            MockHttpServletResponse jsonResponse = new MockHttpServletResponse();

            handler.complete(json, jsonResponse, authentication(), factorContext());

            assertThat(writtenBody(jsonResponse)).containsEntry("redirectUrl", "/admin");
        }

        @Test
        @DisplayName("An intent recorded for another MFA session is discarded and the regular target is kept")
        void intentOfAnotherMfaSessionIsDiscarded() throws Exception {
            TestHandler handler = sessionHandler();
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/mfa-ott");
            request.addHeader("Accept", "text/html");
            MfaPasskeyRegistrationIntent.record(request, "previous-mfa-session-id");
            MockHttpServletResponse response = new MockHttpServletResponse();

            handler.complete(request, response, authentication(), factorContext());

            assertThat(response.getRedirectedUrl()).isEqualTo("/admin");
            assertThat(request.getSession(false).getAttribute(MfaPasskeyRegistrationIntent.SESSION_ATTRIBUTE)).isNull();
            assertThat(MfaPasskeyRegistrationIntent.getReturnUrl(request)).isNull();
        }

        private TestHandler sessionHandler() {
            AuthContextProperties properties = new AuthContextProperties();
            properties.setStateType(StateType.SESSION);
            return newHandler(properties, null, responseWriter, new AuthUrlProvider(properties));
        }

        private FactorContext factorContext() {
            FactorContext factorContext = mock(FactorContext.class);
            when(factorContext.getMfaSessionId()).thenReturn(MFA_SESSION_ID);
            when(factorContext.getFlowTypeName()).thenReturn("mfa");
            return factorContext;
        }

        private Authentication authentication() {
            return new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN");
        }

        @SuppressWarnings("unchecked")
        private Map<String, Object> writtenBody(HttpServletResponse response) throws IOException {
            ArgumentCaptor<Object> bodyCaptor = ArgumentCaptor.forClass(Object.class);
            verify(responseWriter).writeSuccessResponse(eq(response), bodyCaptor.capture(), eq(HttpServletResponse.SC_OK));
            verify(responseWriter, never()).writeErrorResponse(eq(response), anyInt(), anyString(), anyString(),
                    anyString(), anyMap());
            return (Map<String, Object>) bodyCaptor.getValue();
        }
    }

    @Nested
    @DisplayName("Zero Trust challenge release (W1-5)")
    class ChallengeRelease {

        private final ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
        private final SecurityContextDataStore dataStore = mock(SecurityContextDataStore.class);
        private final SecurityLearningService learningService = mock(SecurityLearningService.class);
        private final VerificationLearningService verificationLearning = mock(VerificationLearningService.class);

        @Test
        @DisplayName("a login MFA does not release a CHALLENGE and is recorded as a login MFA")
        void loginMfaDoesNotReleaseAChallenge() throws Exception {
            when(actionRepository.getActionFromHash("admin")).thenReturn(ZeroTrustAction.CHALLENGE);
            FactorContext factorContext = completedFactorContext(false);

            handler().complete(requestWithSession(), new MockHttpServletResponse(),
                    new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN"), factorContext);

            verify(actionRepository, never()).saveActionWithPrevious(anyString(), any(), any());
            verify(learningService, never()).learnAndStore(anyString(), any(), any());
            ArgumentCaptor<String> record = ArgumentCaptor.forClass(String.class);
            verify(dataStore).addSessionAction(eq("session-1"), record.capture());
            assertThat(record.getValue()).contains("MFA_LOGIN").doesNotContain("CHALLENGE", "MFA_COMPLETED");
        }

        @Test
        @DisplayName("the MFA the challenge flow started releases the CHALLENGE and is recorded as a passed challenge")
        void challengeMfaReleasesTheChallenge() throws Exception {
            when(actionRepository.getActionFromHash("admin")).thenReturn(ZeroTrustAction.CHALLENGE);
            FactorContext factorContext = completedFactorContext(true);

            handler().complete(requestWithSession(), new MockHttpServletResponse(),
                    new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN"), factorContext);

            verify(actionRepository).saveActionWithPrevious(eq("admin"), eq(ZeroTrustAction.ALLOW), any());
            ArgumentCaptor<String> record = ArgumentCaptor.forClass(String.class);
            verify(dataStore).addSessionAction(eq("session-1"), record.capture());
            assertThat(record.getValue()).contains("ZERO_TRUST_CHALLENGE_VERIFIED");
        }

        @Test
        @DisplayName("the passed step-up learns the request the challenge stopped from its own facts (W5-2)")
        void challengeMfaLearnsTheChallengedRequest() throws Exception {
            when(actionRepository.getActionFromHash("admin")).thenReturn(ZeroTrustAction.CHALLENGE);
            when(actionRepository.getAnalysisData("admin")).thenReturn(new ZeroTrustActionRepository.ZeroTrustAnalysisData(
                    "CHALLENGE", 0.6, 0.8, null, 1, null, null, null, "request-1", null, null));
            when(verificationLearning.learnStepUp("admin", "request-1")).thenReturn(true);

            handler().complete(requestWithSession(), new MockHttpServletResponse(),
                    new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN"), completedFactorContext(true));

            verify(verificationLearning).learnStepUp("admin", "request-1");
            verify(learningService, never()).learnAndStore(anyString(), any(), any());
        }

        @Test
        @DisplayName("without the facts of the challenged request the step-up is learned as before (W5-2)")
        void challengeMfaWithoutHeldFactsLearnsAsBefore() throws Exception {
            when(actionRepository.getActionFromHash("admin")).thenReturn(ZeroTrustAction.CHALLENGE);
            when(actionRepository.getAnalysisData("admin")).thenReturn(new ZeroTrustActionRepository.ZeroTrustAnalysisData(
                    "CHALLENGE", 0.6, 0.8, null, 1, null, null, null, "request-2", null, null));
            when(verificationLearning.learnStepUp("admin", "request-2")).thenReturn(false);

            handler().complete(requestWithSession(), new MockHttpServletResponse(),
                    new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN"), completedFactorContext(true));

            verify(verificationLearning).learnStepUp("admin", "request-2");
            verify(learningService).learnAndStore(eq("admin"), any(), any());
        }

        @Test
        @DisplayName("on the OAuth2 state a login MFA is recorded under the login the issued token carries as its sid")
        void oauth2LoginMfaIsRecordedUnderTheTokenSession() throws Exception {
            UsernamePasswordAuthenticationToken login = UsernamePasswordAuthenticationToken.authenticated(
                    "admin", "pw", List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));

            handler(StateType.OAUTH2).complete(requestWithSession(), new MockHttpServletResponse(), login,
                    completedFactorContext(false));

            String loginId = ((LoginFactsDetails) login.getDetails()).getSignInId();
            ArgumentCaptor<String> record = ArgumentCaptor.forClass(String.class);
            verify(dataStore).addSessionAction(eq(loginId), record.capture());
            verify(dataStore, never()).addSessionAction(eq("session-1"), anyString());
            assertThat(record.getValue()).contains("MFA_LOGIN");
        }

        @Test
        @DisplayName("on the OAuth2 state a passed challenge is recorded under the login of the challenged token")
        void oauth2ChallengeIsRecordedUnderTheTokenSession() throws Exception {
            Jwt token = Jwt.withTokenValue("token").header("alg", "RS256").subject("admin")
                    .claim("auth_time", 1_791_626_134L).claim("amr", List.of("pwd")).claim("acr", "AAL1")
                    .claim("sid", "login-7").build();
            when(actionRepository.getActionFromHash("admin")).thenReturn(ZeroTrustAction.CHALLENGE);
            FactorContext factorContext = completedFactorContext(true, new JwtAuthenticationToken(token));

            handler(StateType.OAUTH2).complete(requestWithSession(), new MockHttpServletResponse(),
                    new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN"), factorContext);

            ArgumentCaptor<String> record = ArgumentCaptor.forClass(String.class);
            verify(dataStore).addSessionAction(eq("login-7"), record.capture());
            verify(dataStore, never()).addSessionAction(eq("session-1"), anyString());
            assertThat(record.getValue()).contains("ZERO_TRUST_CHALLENGE_VERIFIED");
        }

        private FactorContext completedFactorContext(boolean challengeFlow) {
            return completedFactorContext(challengeFlow, new TestingAuthenticationToken("admin", "pw", "ROLE_ADMIN"));
        }

        private FactorContext completedFactorContext(boolean challengeFlow, Authentication primary) {
            FactorContext factorContext = new FactorContext("mfa-session-1", primary, MfaState.NONE, "mfa");
            factorContext.changeState(MfaState.MFA_SUCCESSFUL);
            if (challengeFlow) {
                factorContext.setAttribute("challengeInitiated", true);
            }
            return factorContext;
        }

        private MockHttpServletRequest requestWithSession() {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/admin/login/mfa-ott");
            request.addHeader("Accept", "application/json");
            request.setSession(new MockHttpSession(null, "session-1"));
            return request;
        }

        private TestHandler handler() {
            return handler(StateType.SESSION);
        }

        private TestHandler handler(StateType stateType) {
            AuthContextProperties properties = new AuthContextProperties();
            properties.setStateType(stateType);
            TokenService tokenService = mock(TokenService.class);
            when(tokenService.createTokenPair(any(), any(), any(), any()))
                    .thenReturn(TokenPair.builder().accessToken("access").refreshToken("refresh").build());
            when(tokenService.prepareTokensForTransport("access", "refresh"))
                    .thenReturn(TokenTransportResult.builder().body(Map.of("accessToken", "access")).build());
            AISessionSecurityContextRepository aiRepository = mock(AISessionSecurityContextRepository.class);
            @SuppressWarnings("unchecked")
            ObjectProvider<AISessionSecurityContextRepository> provider = mock(ObjectProvider.class);
            ApplicationContext applicationContext = mock(ApplicationContext.class);
            when(applicationContext.getBeanProvider(AISessionSecurityContextRepository.class)).thenReturn(provider);
            when(provider.getIfAvailable()).thenReturn(aiRepository);
            when(applicationContext.getBean(SecurityContextDataStore.class)).thenReturn(dataStore);
            @SuppressWarnings("unchecked")
            ObjectProvider<VerificationLearningService> verificationProvider = mock(ObjectProvider.class);
            when(applicationContext.getBeanProvider(VerificationLearningService.class)).thenReturn(verificationProvider);
            when(verificationProvider.getIfAvailable()).thenReturn(verificationLearning);
            return new TestHandler(
                    tokenService,
                    mock(AuthResponseWriter.class),
                    mock(MfaSessionRepository.class),
                    mock(MfaStateMachineIntegrator.class),
                    properties,
                    mock(ZeroTrustEventPublisher.class),
                    actionRepository,
                    learningService,
                    applicationContext,
                    mock(AuthUrlProvider.class),
                    mock(MfaFlowUrlRegistry.class),
                    mock(IBlockedUserRecorder.class),
                    mock(BlockMfaStateStore.class),
                    mock(CentralAuditFacade.class),
                    mock(BlockingSignalBroadcaster.class),
                    false
            );
        }
    }

    private TestHandler newHandler(AuthContextProperties properties, TokenService tokenService) {
        return newHandler(properties, tokenService, mock(AuthResponseWriter.class), mock(AuthUrlProvider.class));
    }

    private TestHandler newHandler(AuthContextProperties properties,
                                   TokenService tokenService,
                                   AuthResponseWriter responseWriter,
                                   AuthUrlProvider authUrlProvider) {
        AISessionSecurityContextRepository aiRepository = mock(AISessionSecurityContextRepository.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<AISessionSecurityContextRepository> provider = mock(ObjectProvider.class);
        ApplicationContext applicationContext = mock(ApplicationContext.class);
        when(applicationContext.getBeanProvider(AISessionSecurityContextRepository.class)).thenReturn(provider);
        when(provider.getIfAvailable()).thenReturn(aiRepository);

        return new TestHandler(
                tokenService,
                responseWriter,
                mock(MfaSessionRepository.class),
                mock(MfaStateMachineIntegrator.class),
                properties,
                mock(ZeroTrustEventPublisher.class),
                mock(ZeroTrustActionRepository.class),
                mock(SecurityLearningService.class),
                applicationContext,
                authUrlProvider,
                mock(MfaFlowUrlRegistry.class),
                mock(IBlockedUserRecorder.class),
                mock(BlockMfaStateStore.class),
                mock(CentralAuditFacade.class),
                mock(BlockingSignalBroadcaster.class),
                false
        );
    }

    private static final class TestHandler extends AbstractMfaAuthenticationSuccessHandler {

        private final boolean failOnBuildResponse;

        private TestHandler(TokenService tokenService,
                            AuthResponseWriter responseWriter,
                            MfaSessionRepository sessionRepository,
                            MfaStateMachineIntegrator stateMachineIntegrator,
                            AuthContextProperties authContextProperties,
                            ZeroTrustEventPublisher zeroTrustEventPublisher,
                            ZeroTrustActionRepository actionRedisRepository,
                            SecurityLearningService securityLearningService,
                            ApplicationContext applicationContext,
                            AuthUrlProvider authUrlProvider,
                            MfaFlowUrlRegistry mfaFlowUrlRegistry,
                            IBlockedUserRecorder blockedUserRecorder,
                            BlockMfaStateStore blockMfaStateStore,
                            CentralAuditFacade centralAuditFacade,
                            BlockingSignalBroadcaster blockingSignalBroadcaster,
                            boolean failOnBuildResponse) {
            super(tokenService, responseWriter, sessionRepository, stateMachineIntegrator, authContextProperties,
                    zeroTrustEventPublisher, actionRedisRepository, securityLearningService, applicationContext,
                    authUrlProvider, mfaFlowUrlRegistry, blockedUserRecorder, blockMfaStateStore,
                    centralAuditFacade, blockingSignalBroadcaster);
            this.failOnBuildResponse = failOnBuildResponse;
        }

        private void complete(HttpServletRequest request,
                              HttpServletResponse response,
                              Authentication authentication) throws IOException {
            handleFinalAuthenticationSuccess(request, response, authentication, null);
        }

        private void complete(HttpServletRequest request,
                              HttpServletResponse response,
                              Authentication authentication,
                              FactorContext factorContext) throws IOException {
            handleFinalAuthenticationSuccess(request, response, authentication, factorContext);
        }

        @Override
        protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
            if (failOnBuildResponse) {
                throw new IllegalStateException("boom");
            }
            return "/admin";
        }

        @Override
        protected Map<String, Object> buildResponseData(TokenTransportResult transportResult,
                                                        Authentication authentication,
                                                        HttpServletRequest request,
                                                        HttpServletResponse response) {
            return Map.of();
        }
    }
}
