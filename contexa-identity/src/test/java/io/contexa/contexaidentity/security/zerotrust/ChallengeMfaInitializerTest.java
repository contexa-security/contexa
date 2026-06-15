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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ChallengeMfaInitializerTest {

    @Mock
    private MfaSessionRepository sessionRepository;
    @Mock
    private MfaStateMachineIntegrator stateMachineIntegrator;
    @Mock
    private MfaPolicyProvider mfaPolicyProvider;
    @Mock
    private PlatformConfig platformConfig;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private Authentication authentication;

    private ChallengeMfaInitializer initializer;

    @BeforeEach
    void setUp() {
        initializer = new ChallengeMfaInitializer(
                sessionRepository,
                stateMachineIntegrator,
                mfaPolicyProvider,
                platformConfig
        );

        when(request.getRequestURI()).thenReturn("/login");
        when(request.getContextPath()).thenReturn("");
        when(authentication.getName()).thenReturn("testUser");
    }

    @Test
    @DisplayName("initializeChallengeFlow successfully initializes state machine and triggers auto challenge")
    void initializeChallengeFlowSuccess() {
        AuthenticationStepConfig step1 = new AuthenticationStepConfig();
        step1.setStepId("step-primary");
        step1.setType("PASSKEY");
        step1.setOrder(1);

        AuthenticationStepConfig step2 = new AuthenticationStepConfig();
        step2.setStepId("step-mfa");
        step2.setType("PASSKEY");
        step2.setOrder(2);

        AuthenticationFlowConfig flowConfig = AuthenticationFlowConfig.builder("mfa-flow")
                .stepConfigs(List.of(step1, step2))
                .primaryAuthenticationOptions(mock(PrimaryAuthenticationOptions.class))
                .registeredFactorOptions(Map.of(AuthType.PASSKEY, mock(AuthenticationProcessingOptions.class)))
                .build();

        when(platformConfig.getFlows()).thenReturn(List.of(flowConfig));
        when(request.getAttribute("io.contexa.currentFlowConfig")).thenReturn(flowConfig);

        MfaDecision mfaDecision = MfaDecision.builder()
                .required(true)
                .type(MfaDecision.DecisionType.CHALLENGED)
                .requiredFactors(List.of(AuthType.PASSKEY))
                .build();
        when(mfaPolicyProvider.evaluateInitialMfaRequirement(any(FactorContext.class))).thenReturn(mfaDecision);

        when(stateMachineIntegrator.sendEvent(eq(MfaEvent.ADAPTIVE_MFA_REQUIRED), any(), any(), any())).thenReturn(true);
        when(stateMachineIntegrator.sendEvent(eq(MfaEvent.INITIATE_CHALLENGE_AUTO), any(), any())).thenReturn(true);

        FactorContext returnedContext = mock(FactorContext.class);
        when(returnedContext.getMfaSessionId()).thenReturn("session-abc");
        when(returnedContext.getFlowTypeName()).thenReturn("mfa-flow");
        when(returnedContext.getRemainingFactors()).thenReturn(Set.of(AuthType.PASSKEY));
        when(stateMachineIntegrator.loadFactorContext(anyString())).thenReturn(returnedContext);

        FactorContext context = initializer.initializeChallengeFlow(request, response, authentication);

        assertThat(context).isNotNull();
        verify(stateMachineIntegrator).initializeStateMachine(any(FactorContext.class), eq(request), eq(response));
        verify(stateMachineIntegrator).sendEvent(eq(MfaEvent.ADAPTIVE_MFA_REQUIRED), any(), eq(request), any());
        verify(stateMachineIntegrator).sendEvent(eq(MfaEvent.INITIATE_CHALLENGE_AUTO), any(), eq(request));
    }

    @Test
    @DisplayName("initializeChallengeFlow throws exception on state machine event failure and cleans up session")
    void initializeChallengeFlowThrowsOnEventFailure() {
        AuthenticationStepConfig step1 = new AuthenticationStepConfig();
        step1.setStepId("step-primary");
        step1.setType("PASSKEY");
        step1.setOrder(1);

        AuthenticationStepConfig step2 = new AuthenticationStepConfig();
        step2.setStepId("step-mfa");
        step2.setType("PASSKEY");
        step2.setOrder(2);

        AuthenticationFlowConfig flowConfig = AuthenticationFlowConfig.builder("mfa-flow")
                .stepConfigs(List.of(step1, step2))
                .primaryAuthenticationOptions(mock(PrimaryAuthenticationOptions.class))
                .build();

        when(platformConfig.getFlows()).thenReturn(List.of(flowConfig));
        when(request.getAttribute("io.contexa.currentFlowConfig")).thenReturn(flowConfig);

        MfaDecision mfaDecision = MfaDecision.builder().required(true).build();
        when(mfaPolicyProvider.evaluateInitialMfaRequirement(any(FactorContext.class))).thenReturn(mfaDecision);

        when(stateMachineIntegrator.sendEvent(eq(MfaEvent.ADAPTIVE_MFA_REQUIRED), any(), any(), any())).thenReturn(false);
        when(sessionRepository.existsSession(anyString())).thenReturn(true);

        assertThatThrownBy(() -> initializer.initializeChallengeFlow(request, response, authentication))
                .isInstanceOf(ChallengeMfaInitializer.ChallengeMfaInitializationException.class)
                .hasMessageContaining("Failed to initialize state machine with ADAPTIVE_MFA_REQUIRED event");

        verify(stateMachineIntegrator).releaseStateMachine(anyString());
        verify(sessionRepository).removeSession(anyString(), eq(request), eq(response));
    }
}
