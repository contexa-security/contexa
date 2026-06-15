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
package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.exception.MfaStateMachineExceptions.StateMachineActionException;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateContext;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaStateActionTest {

    @Mock
    private StateContext<MfaState, MfaEvent> stateContext;

    @Mock
    private FactorContext factorContext;

    @Mock
    private ExtendedState extendedState;

    @Mock
    private MfaSettings mfaSettings;

    @Mock
    private PlatformConfig platformConfig;

    private MockedStatic<StateContextHelper> helperMock;

    @BeforeEach
    void setUp() {
        helperMock = mockStatic(StateContextHelper.class);
        helperMock.when(() -> StateContextHelper.getFactorContext(any(StateContext.class))).thenReturn(factorContext);
        when(stateContext.getExtendedState()).thenReturn(extendedState);
        when(extendedState.getVariables()).thenReturn(new HashMap<>());
        when(factorContext.getMfaSessionId()).thenReturn("session-123");
        when(factorContext.getUsername()).thenReturn("testUser");
        when(factorContext.getFlowTypeName()).thenReturn("mfa-flow");
    }

    @AfterEach
    void tearDown() {
        helperMock.close();
    }

    // ==========================================
    // CompleteMfaAction Tests
    // ==========================================

    @Test
    @DisplayName("CompleteMfaAction: logs completed factors")
    void completeMfaActionSuccess() throws Exception {
        CompleteMfaAction action = new CompleteMfaAction();
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        step.setType("SMS");
        when(factorContext.getCompletedFactors()).thenReturn(List.of(step));

        action.execute(stateContext);

        // 예외 없이 완료됨을 확인
        verify(factorContext).getCompletedFactors();
    }

    // ==========================================
    // HandleFailureAction Tests
    // ==========================================

    @Test
    @DisplayName("HandleFailureAction: updates retry count and stores failure details")
    void handleFailureActionUpdatesDetails() throws Exception {
        HandleFailureAction action = new HandleFailureAction(mfaSettings);
        when(mfaSettings.getMaxRetryAttempts()).thenReturn(3);
        when(stateContext.getMessageHeader("failureReason")).thenReturn("INVALID_OTP");
        when(factorContext.getRetryCount()).thenReturn(1);
        when(factorContext.getCurrentProcessingFactor()).thenReturn(AuthType.PASSKEY);
        when(factorContext.getAttemptCount(AuthType.PASSKEY)).thenReturn(2);

        action.execute(stateContext);

        verify(factorContext).setLastError("INVALID_OTP");
        verify(factorContext).setRetryCount(2);
        verify(factorContext).setAttribute("retryCount_PASSKEY", 2);
    }

    // ==========================================
    // VerifyFactorAction Tests
    // ==========================================

    @Test
    @DisplayName("VerifyFactorAction: adds completed step, increments success and resets retry")
    void verifyFactorActionSuccess() throws Exception {
        VerifyFactorAction action = new VerifyFactorAction(platformConfig);

        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig();
        stepConfig.setStepId("step-1");
        stepConfig.setType("PASSKEY");
        stepConfig.setOrder(1);
        stepConfig.setRequired(true);

        AuthenticationFlowConfig flowConfig = AuthenticationFlowConfig.builder("non-mfa")
                .stepConfigs(List.of(stepConfig))
                .build();

        when(platformConfig.getFlows()).thenReturn(List.of(flowConfig));
        when(factorContext.getCurrentStepId()).thenReturn("step-1");
        when(factorContext.getCurrentProcessingFactor()).thenReturn(AuthType.PASSKEY);
        when(factorContext.getAttribute(FactorContextAttributes.StateControl.VERIFICATION_SUCCESS_COUNT)).thenReturn(1);

        action.execute(stateContext);

        verify(factorContext).addCompletedFactor(any(AuthenticationStepConfig.class));
        verify(factorContext).setAttribute(FactorContextAttributes.StateControl.VERIFICATION_SUCCESS_COUNT, 2);
        verify(factorContext).setRetryCount(0);
    }

    @Test
    @DisplayName("VerifyFactorAction: throws IllegalStateException when factor type cannot be determined")
    void verifyFactorActionThrowsOnUnknownFactor() {
        VerifyFactorAction action = new VerifyFactorAction(platformConfig);
        when(platformConfig.getFlows()).thenReturn(Collections.emptyList());
        when(factorContext.getCurrentStepId()).thenReturn("unknown-step");
        when(factorContext.getCurrentProcessingFactor()).thenReturn(null);

        assertThatThrownBy(() -> action.execute(stateContext))
                .isInstanceOf(StateMachineActionException.class)
                .hasCauseInstanceOf(IllegalStateException.class);
    }
}
