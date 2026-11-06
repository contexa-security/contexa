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

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A sign-in the policy blocked tells the person only that it is blocked: how risky it was judged, why, and under which
 * name tell whoever tries a password how close a guess came and what to change, and an address of no one invites mail
 * that reaches no one. The operators keep all of it in the log and the audit.
 */
class AuthenticationBlockedResponseTest {

    private static final String MFA_SESSION_ID = "mfa-session-id";

    private final Authentication authentication =
            UsernamePasswordAuthenticationToken.authenticated("victim", null, List.of());
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
    private final MfaPolicyProvider mfaPolicyProvider = mock(MfaPolicyProvider.class);
    private FactorContext factorContext;
    private PrimaryAuthenticationSuccessHandler handler;

    @BeforeEach
    void setUp() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setStateType(StateType.SESSION);
        MfaStateMachineIntegrator stateMachineIntegrator = mock(MfaStateMachineIntegrator.class);
        MfaSessionRepository sessionRepository = mock(MfaSessionRepository.class);
        handler = new PrimaryAuthenticationSuccessHandler(mfaPolicyProvider, null, responseWriter, properties,
                mock(ApplicationContext.class), stateMachineIntegrator, sessionRepository, new AuthUrlProvider(properties),
                new MfaFlowUrlRegistry(properties), mock(ZeroTrustEventPublisher.class),
                mock(ZeroTrustActionRepository.class), mock(SecurityLearningService.class),
                mock(IBlockedUserRecorder.class), mock(BlockMfaStateStore.class), audit,
                mock(BlockingSignalBroadcaster.class), null);
        factorContext = new FactorContext(MFA_SESSION_ID, authentication, MfaState.NONE, "mfa");
        factorContext.setAttribute("blockReason", "Zero Trust BLOCK action");
        factorContext.setAttribute("aiRiskScore", 0.93);
        when(sessionRepository.getSessionId(any(HttpServletRequest.class))).thenReturn(MFA_SESSION_ID);
        when(stateMachineIntegrator.loadFactorContext(MFA_SESSION_ID)).thenReturn(factorContext);
        when(stateMachineIntegrator.sendEvent(eq(MfaEvent.PRIMARY_AUTH_SUCCESS), any(FactorContext.class),
                any(HttpServletRequest.class), anyMap())).thenReturn(true);
        when(mfaPolicyProvider.evaluateInitialMfaRequirement(factorContext)).thenReturn(MfaDecision.blocked("risk"));
    }

    private MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/mfa/login");
        request.addHeader("Accept", "application/json");
        request.addHeader("User-Agent", "browser/1.0");
        return request;
    }

    @Test
    @DisplayName("the response holds no risk score, no reason, no name and no made-up contact")
    void theResponseTellsOnlyThatItIsBlocked() throws Exception {
        handler.onAuthenticationSuccess(request(), new MockHttpServletResponse(), authentication);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> body = ArgumentCaptor.forClass(Map.class);
        ArgumentCaptor<String> message = ArgumentCaptor.forClass(String.class);
        verify(responseWriter).writeErrorResponse(any(), eq(HttpServletResponse.SC_FORBIDDEN),
                eq("AUTHENTICATION_BLOCKED"), message.capture(), anyString(), body.capture());
        assertThat(body.getValue()).doesNotContainKeys("riskScore", "reason", "username", "supportContact")
                .containsEntry("status", "AUTHENTICATION_BLOCKED").containsEntry("blocked", true);
        assertThat(body.getValue().values()).doesNotContain("victim", 0.93, "Zero Trust BLOCK action",
                "security@example.com");
        assertThat(message.getValue()).doesNotContain("victim", "0.93", "Zero Trust BLOCK action");
    }

    @Test
    @DisplayName("the audit keeps who it was, the risk score and the reason")
    void theAuditKeepsEverything() throws Exception {
        handler.onAuthenticationSuccess(request(), new MockHttpServletResponse(), authentication);

        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(record.capture());
        AuditRecord kept = record.getValue();
        assertThat(kept.getEventCategory()).isEqualTo(AuditEventCategory.AUTHENTICATION_FAILURE);
        assertThat(kept.getPrincipalName()).isEqualTo("victim");
        assertThat(kept.getRiskScore()).isEqualTo(0.93);
        assertThat(kept.getReason()).contains("Zero Trust BLOCK action");
        assertThat(kept.getDecision()).isEqualTo("BLOCK");
        assertThat(kept.getUserAgent()).isEqualTo("browser/1.0");
    }
}
