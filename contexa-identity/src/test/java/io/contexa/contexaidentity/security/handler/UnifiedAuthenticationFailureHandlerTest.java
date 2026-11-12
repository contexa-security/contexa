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

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Arrays;
import io.contexa.contexacommon.security.context.RequestSecurityContextAttributes;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexacommon.security.ContexaConsolePaths;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustAccessControlFilter;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.BadCredentialsException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UnifiedAuthenticationFailureHandlerTest {

    @Mock
    private AuthResponseWriter responseWriter;

    @Mock
    private MfaStateMachineIntegrator stateMachineIntegrator;

    @Mock
    private MfaSessionRepository sessionRepository;

    @Mock
    private ZeroTrustActionRepository actionRepository;

    @Mock
    private MfaSettings mfaSettings;

    @Mock
    private IBlockedUserRecorder blockedUserRecorder;

    @Mock
    private SecurityContextDataStore securityContextDataStore;

    private UnifiedAuthenticationFailureHandler handler;

    @BeforeEach
    void setUp() {
        handler = new UnifiedAuthenticationFailureHandler(
                responseWriter,
                stateMachineIntegrator,
                sessionRepository,
                actionRepository,
                mfaSettings,
                blockedUserRecorder,
                null,
                securityContextDataStore
        );
    }

    /** Sent to /password-change, which nothing answers: an expired account could never change its password. */
    @Test
    void anExpiredPasswordIsSentToWhereThePasswordIsChanged() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setParameter("username", "admin");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(null);

        handler.onAuthenticationFailure(request, response, new CredentialsExpiredException("expired"));

        // the account goes to the page in the session: an address is kept by browsers and proxies
        assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/password-change?expired=true");
        assertThat(request.getSession(false)).isNotNull();
        assertThat(request.getSession(false).getAttribute(ContexaConsolePaths.PASSWORD_CHANGE_USERNAME_ATTRIBUTE))
                .isEqualTo("admin");
    }

    /** A script followed the redirect and read the HTML of the page as JSON: it gets the code and the page instead. */
    @Test
    void aScriptWithAnExpiredPasswordGetsTheCodeAndThePageToGoOn() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/mfa/login");
        request.addHeader("Accept", "application/json");
        request.setParameter("username", "admin");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(null);

        handler.onAuthenticationFailure(request, response, new CredentialsExpiredException("expired"));

        assertThat(response.getRedirectedUrl()).isNull();
        verify(responseWriter).writeErrorResponse(same(response), eq(401), eq("CREDENTIALS_EXPIRED"),
                anyString(), anyString(), argThat(details -> "/contexa/password-change?expired=true".equals(details.get("nextStepUrl"))));
        assertThat(request.getSession(false).getAttribute(ContexaConsolePaths.PASSWORD_CHANGE_USERNAME_ATTRIBUTE))
                .isEqualTo("admin");
    }

    @Test
    void aFailedBlockMfaOfAUserNamedAsTheConsolesKeyCountsAgainstThatUser() throws Exception {
        String own = ZeroTrustUserKey.person("console::rcboss");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/mfa-ott");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FactorContext context = mock(FactorContext.class);
        when(context.getUsername()).thenReturn("console::rcboss");
        when(context.getMfaSessionId()).thenReturn("mfa-session-1");
        when(context.getCurrentProcessingFactor()).thenReturn(AuthType.MFA_OTT);
        when(context.getCurrentState()).thenReturn(MfaState.FACTOR_VERIFICATION_PENDING, MfaState.MFA_RETRY_LIMIT_EXCEEDED);
        when(context.getAttribute(ZeroTrustAccessControlFilter.BLOCK_MFA_FLOW_ATTRIBUTE)).thenReturn(true);
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(context);
        when(sessionRepository.existsSession("mfa-session-1")).thenReturn(true);
        when(actionRepository.incrementBlockMfaFailCount(own)).thenReturn(1L);

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad code"));

        verify(actionRepository).incrementBlockMfaFailCount(own);
        verify(actionRepository, never()).incrementBlockMfaFailCount("console::rcboss");
    }

    /**
     * The MFA session ended, by its time or a restart, and the code is submitted after it: that is no guess at a password,
     * and counting it would lock the user who only came back late. It is answered and audited, and counts against no
     * account.
     */
    @Test
    void anMfaSubmissionWhoseSessionIsGoneCountsAgainstNoAccount() throws Exception {
        Logger logger = (Logger) LoggerFactory.getLogger(UnifiedAuthenticationFailureHandler.class);
        ListAppender<ILoggingEvent> lines = new ListAppender<>();
        lines.start();
        logger.addAppender(lines);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/mfa-ott");
        request.setParameter("username", "alice");
        request.setParameter("token", "123456");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(null);
        try {
            handler.onAuthenticationFailure(request, response, new BadCredentialsException("Invalid token"));
        } finally {
            logger.detachAppender(lines);
        }

        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=primary_auth_failed");
        assertThat(lines.list).noneMatch(line -> line.getLevel() == Level.ERROR);
        theHandlerCountsNoAccountFailure();
    }

    /** The account's failures are the failure event's to count: the handler has no way to count one. */
    @Test
    void theHandlerCountsNoAccountFailure() {
        assertThat(Arrays.stream(UnifiedAuthenticationFailureHandler.class.getDeclaredFields()).map(Field::getType))
                .doesNotContain(LoginPolicyHandler.class);
        assertThat(Arrays.stream(UnifiedAuthenticationFailureHandler.class.getConstructors())
                .flatMap(constructor -> Arrays.stream(constructor.getParameterTypes())))
                .doesNotContain(LoginPolicyHandler.class);
    }

    @Test
    void primaryAuthenticationFailureRecordsAuthenticationContext() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setParameter("username", "admin");
        request.setRemoteAddr("203.0.113.10");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(null);

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));

        verify(securityContextDataStore).recordLoginFailure(eq("admin"), isNull(), anyLong());
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=primary_auth_failed");
    }

    @Test
    void primaryAuthenticationFailureIsRecordedAtTheRequestObservedTime() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setParameter("username", "admin");
        Instant observedAt = Instant.parse("2026-09-30T03:14:00Z");
        RequestSecurityContextAttributes.write(request, RequestSecurityContextAttributes.Field.OBSERVED_AT,
                observedAt.toString(), true);
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(null);

        handler.onAuthenticationFailure(request, new MockHttpServletResponse(), new BadCredentialsException("bad credentials"));

        // The failure window is read on the request clock, so the failure is kept on it too (W1-7).
        verify(securityContextDataStore).recordLoginFailure(eq("admin"), isNull(), eq(observedAt.toEpochMilli()));
    }

    @Test
    void primaryAuthenticationFailureWithoutSubmittedPrincipalDoesNotPoisonAuthenticationContext() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(null);

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));

        verify(securityContextDataStore, never()).recordLoginFailure(eq("UnknownUser"), isNull(), anyLong());
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=primary_auth_failed");
    }
}
