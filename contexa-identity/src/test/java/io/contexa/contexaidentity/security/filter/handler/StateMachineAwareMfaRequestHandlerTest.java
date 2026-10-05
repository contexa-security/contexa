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
package io.contexa.contexaidentity.security.filter.handler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPasskeyRegistrationIntent;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class StateMachineAwareMfaRequestHandlerTest {

    private static final String MFA_SESSION_ID = "mfa-session-id";

    @Mock
    private AuthResponseWriter responseWriter;
    @Mock
    private ApplicationContext applicationContext;
    @Mock
    private MfaStateMachineIntegrator stateMachineIntegrator;
    @Mock
    private MfaSessionRepository sessionRepository;
    @Mock
    private PlatformConfig platformConfig;

    private FactorContext context;
    private StateMachineAwareMfaRequestHandler handler;

    @BeforeEach
    void setUp() {
        AuthContextProperties properties = new AuthContextProperties();
        MfaFlowUrlRegistry mfaFlowUrlRegistry = new MfaFlowUrlRegistry(properties);
        mfaFlowUrlRegistry.createAndRegister("mfa", null, null, null);

        when(applicationContext.getBean(PlatformConfig.class)).thenReturn(platformConfig);
        when(platformConfig.getFlows()).thenReturn(List.of());

        // The user is on the passkey challenge of the pending MFA flow.
        context = new FactorContext(MFA_SESSION_ID,
                UsernamePasswordAuthenticationToken.authenticated("user", null, List.of()),
                MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION, "mfa");
        context.setCurrentProcessingFactor(AuthType.MFA_PASSKEY);
        when(stateMachineIntegrator.loadFactorContextFromRequest(any(HttpServletRequest.class))).thenReturn(context);

        // Model the state machine transitions of the factor switch.
        when(stateMachineIntegrator.sendEvent(eq(MfaEvent.MFA_REQUIRED_SELECT_FACTOR), eq(context), any(HttpServletRequest.class)))
                .thenAnswer(invocation -> {
                    context.changeState(MfaState.AWAITING_FACTOR_SELECTION);
                    return true;
                });
        when(stateMachineIntegrator.sendEvent(eq(MfaEvent.FACTOR_SELECTED), eq(context), any(HttpServletRequest.class)))
                .thenAnswer(invocation -> {
                    context.setCurrentProcessingFactor(AuthType.valueOf((String) context.getAttribute("selectedFactor")));
                    context.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
                    return true;
                });
        when(stateMachineIntegrator.sendEvent(eq(MfaEvent.INITIATE_CHALLENGE), eq(context), any(HttpServletRequest.class)))
                .thenAnswer(invocation -> {
                    context.changeState(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
                    return true;
                });

        handler = new StateMachineAwareMfaRequestHandler(properties, responseWriter, applicationContext,
                stateMachineIntegrator, new AuthUrlProvider(properties), sessionRepository, mfaFlowUrlRegistry);
    }

    @Test
    @DisplayName("Form submit of the passkey page button records the intent and moves to the OTT step through the state machine")
    void formSubmitRecordsIntentAndSwitchesToOtt() throws Exception {
        MockHttpServletRequest request = selectFactorRequest();
        request.setParameter("factorType", AuthType.MFA_OTT.name());
        request.setParameter(MfaPasskeyRegistrationIntent.REQUEST_PARAMETER, "true");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handleRequest(MfaRequestType.FACTOR_SELECTION, request, response, context, new MockFilterChain());

        InOrder events = inOrder(stateMachineIntegrator);
        events.verify(stateMachineIntegrator).sendEvent(eq(MfaEvent.MFA_REQUIRED_SELECT_FACTOR), eq(context), eq(request));
        events.verify(stateMachineIntegrator).sendEvent(eq(MfaEvent.FACTOR_SELECTED), eq(context), eq(request));
        events.verify(stateMachineIntegrator).sendEvent(eq(MfaEvent.INITIATE_CHALLENGE), eq(context), eq(request));
        assertThat(context.getCurrentProcessingFactor()).isEqualTo(AuthType.MFA_OTT);
        assertThat(successResponse(response))
                .containsEntry("status", "FACTOR_SELECTED")
                .containsEntry("selectedFactor", "MFA_OTT")
                .containsEntry("nextStepUrl", "/mfa/ott/request-code-ui");
        assertThat(MfaPasskeyRegistrationIntent.consume(request, MFA_SESSION_ID)).isTrue();
    }

    @Test
    @DisplayName("SDK JSON request with the intent field records the intent")
    void jsonRequestRecordsIntent() throws Exception {
        MockHttpServletRequest request = selectFactorRequest();
        request.setContentType("application/json");
        request.setContent("{\"factorType\":\"MFA_OTT\",\"username\":\"user\",\"registerPasskeyAfterMfa\":true}"
                .getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handleRequest(MfaRequestType.FACTOR_SELECTION, request, response, context, new MockFilterChain());

        assertThat(successResponse(response)).containsEntry("nextStepUrl", "/mfa/ott/request-code-ui");
        assertThat(MfaPasskeyRegistrationIntent.consume(request, MFA_SESSION_ID)).isTrue();
    }

    @Test
    @DisplayName("Regular factor selection does not record the intent")
    void regularSelectionDoesNotRecordIntent() throws Exception {
        MockHttpServletRequest request = selectFactorRequest();
        request.setContentType("application/json");
        request.setContent("{\"factorType\":\"MFA_OTT\"}".getBytes(StandardCharsets.UTF_8));

        handler.handleRequest(MfaRequestType.FACTOR_SELECTION, request, new MockHttpServletResponse(), context,
                new MockFilterChain());

        assertThat(context.getCurrentProcessingFactor()).isEqualTo(AuthType.MFA_OTT);
        assertThat(MfaPasskeyRegistrationIntent.consume(request, MFA_SESSION_ID)).isFalse();
    }

    @Test
    @DisplayName("The intent is accepted only together with the OTT factor")
    void intentWithOtherFactorIsIgnored() throws Exception {
        context.changeState(MfaState.AWAITING_FACTOR_SELECTION);
        context.setCurrentProcessingFactor(null);
        MockHttpServletRequest request = selectFactorRequest();
        request.setParameter("factorType", AuthType.MFA_PASSKEY.name());
        request.setParameter(MfaPasskeyRegistrationIntent.REQUEST_PARAMETER, "true");

        handler.handleRequest(MfaRequestType.FACTOR_SELECTION, request, new MockHttpServletResponse(), context,
                new MockFilterChain());

        assertThat(context.getCurrentProcessingFactor()).isEqualTo(AuthType.MFA_PASSKEY);
        assertThat(MfaPasskeyRegistrationIntent.consume(request, MFA_SESSION_ID)).isFalse();
    }

    @Test
    @DisplayName("A factor selection rejected by the state machine does not record the intent")
    void rejectedSelectionDoesNotRecordIntent() throws Exception {
        when(stateMachineIntegrator.sendEvent(eq(MfaEvent.FACTOR_SELECTED), eq(context), any(HttpServletRequest.class)))
                .thenReturn(false);
        MockHttpServletRequest request = selectFactorRequest();
        request.setParameter("factorType", AuthType.MFA_OTT.name());
        request.setParameter(MfaPasskeyRegistrationIntent.REQUEST_PARAMETER, "true");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handleRequest(MfaRequestType.FACTOR_SELECTION, request, response, context, new MockFilterChain());

        verify(stateMachineIntegrator, never()).sendEvent(eq(MfaEvent.INITIATE_CHALLENGE), eq(context), any(HttpServletRequest.class));
        verify(responseWriter).writeErrorResponse(eq(response), eq(HttpServletResponse.SC_BAD_REQUEST),
                eq("FACTOR_SELECTION_REJECTED"), anyString(), anyString(), anyMap());
        assertThat(MfaPasskeyRegistrationIntent.consume(request, MFA_SESSION_ID)).isFalse();
    }

    private MockHttpServletRequest selectFactorRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/mfa/select-factor");
        request.addHeader("Accept", "application/json");
        return request;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> successResponse(HttpServletResponse response) throws Exception {
        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(responseWriter).writeSuccessResponse(eq(response), captor.capture(), eq(HttpServletResponse.SC_OK));
        return (Map<String, Object>) captor.getValue();
    }
}
