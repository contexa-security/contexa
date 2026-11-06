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

import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A failure of the MFA flow tells the person a general sentence: the exception's own text names what went wrong
 * inside (a store, a key, a state) and is the operators', in the log and the audit.
 */
class MfaFailureMessageTest {

    private static final String INSIDE = "MFA state machine lost for session mfa-7f3e at redis://10.0.0.5:6379";

    private final AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
    private final MfaStateMachineIntegrator stateMachineIntegrator = mock(MfaStateMachineIntegrator.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final UnifiedAuthenticationFailureHandler handler = new UnifiedAuthenticationFailureHandler(responseWriter,
            stateMachineIntegrator, mock(MfaSessionRepository.class), mock(ZeroTrustActionRepository.class),
            mock(MfaSettings.class), mock(IBlockedUserRecorder.class), audit, null);

    @Test
    @DisplayName("the answer holds a general sentence, not the exception's text")
    void theAnswerHoldsAGeneralSentence() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/mfa-ott");
        request.addHeader("Accept", "application/json");
        request.setParameter("username", "alice");
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(null);

        handler.onAuthenticationFailure(request, new MockHttpServletResponse(), new AuthenticationServiceException(INSIDE));

        ArgumentCaptor<String> message = ArgumentCaptor.forClass(String.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(responseWriter).writeErrorResponse(any(), eq(HttpServletResponse.SC_UNAUTHORIZED),
                eq("MFA_GLOBAL_FAILURE"), message.capture(), anyString(), details.capture());
        assertThat(message.getValue()).doesNotContain("state machine", "redis", "mfa-7f3e")
                .isEqualTo("An error occurred during MFA processing. Please sign in again.");
        assertThat(details.getValue().values()).noneMatch(value -> String.valueOf(value).contains("redis"));
    }

    @Test
    @DisplayName("the audit keeps the exception's text")
    void theAuditKeepsIt() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/mfa-ott");
        request.addHeader("Accept", "application/json");
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(null);

        handler.onAuthenticationFailure(request, new MockHttpServletResponse(), new AuthenticationServiceException(INSIDE));

        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(record.capture());
        assertThat(record.getValue().getReason()).isEqualTo(INSIDE);
    }
}
