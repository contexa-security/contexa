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
package io.contexa.contexaidentity.security.statemachine.config;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.statemachine.action.*;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.guard.AllFactorsCompletedGuard;
import io.contexa.contexaidentity.security.statemachine.guard.RetryLimitGuard;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineBuilder;
import org.springframework.statemachine.guard.Guard;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaStateMachineConfigurationTest {

    @Mock
    private InitializeMfaAction initializeMfaAction;
    @Mock
    private SelectFactorAction selectFactorAction;
    @Mock
    private InitiateChallengeAction initiateChallengeAction;
    @Mock
    private VerifyFactorAction verifyFactorAction;
    @Mock
    private CompleteMfaAction completeMfaAction;
    @Mock
    private HandleFailureAction handleFailureAction;
    @Mock
    private DetermineNextFactorAction determineNextFactorAction;

    private AllFactorsCompletedGuard allFactorsCompletedGuard;
    private RetryLimitGuard retryLimitGuard;

    @Mock
    private MfaSettings mfaSettings;

    @Mock
    private MfaPolicyProvider mfaPolicyProvider;

    @Mock
    private FactorContext factorContext;

    private StateMachine<MfaState, MfaEvent> stateMachine;

    @BeforeEach
    void setUp() throws Exception {
        allFactorsCompletedGuard = new AllFactorsCompletedGuard(mfaPolicyProvider);
        retryLimitGuard = new RetryLimitGuard(mfaSettings);

        MfaStateMachineConfiguration configuration = new MfaStateMachineConfiguration(
                initializeMfaAction,
                selectFactorAction,
                initiateChallengeAction,
                verifyFactorAction,
                completeMfaAction,
                handleFailureAction,
                determineNextFactorAction,
                allFactorsCompletedGuard,
                retryLimitGuard
        );

        StateMachineBuilder.Builder<MfaState, MfaEvent> builder = StateMachineBuilder.builder();
        configuration.configure(builder.configureConfiguration());
        configuration.configure(builder.configureStates());
        configuration.configure(builder.configureTransitions());

        stateMachine = builder.build();
        stateMachine.startReactively().block();

        StateContextHelper.setFactorContext(stateMachine, factorContext);
        when(factorContext.getMfaSessionId()).thenReturn("session-123");
    }

    @Test
    @DisplayName("Initial state should be NONE")
    void testInitialState() {
        assertThat(stateMachine.getState().getId()).isEqualTo(MfaState.NONE);
    }

    @Test
    @DisplayName("NONE -> PRIMARY_AUTHENTICATION_COMPLETED on PRIMARY_AUTH_SUCCESS event")
    void testTransitionToPrimaryAuthCompleted() {
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.PRIMARY_AUTH_SUCCESS).build())).blockFirst();
        assertThat(stateMachine.getState().getId()).isEqualTo(MfaState.PRIMARY_AUTHENTICATION_COMPLETED);
        verify(initializeMfaAction, times(1)).execute(any());
    }

    @Test
    @DisplayName("PRIMARY_AUTHENTICATION_COMPLETED -> AWAITING_FACTOR_SELECTION on MFA_REQUIRED_SELECT_FACTOR event")
    void testTransitionToAwaitingFactorSelection() {
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.PRIMARY_AUTH_SUCCESS).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.MFA_REQUIRED_SELECT_FACTOR).build())).blockFirst();
        assertThat(stateMachine.getState().getId()).isEqualTo(MfaState.AWAITING_FACTOR_SELECTION);
    }

    @Test
    @DisplayName("AWAITING_FACTOR_SELECTION -> AWAITING_FACTOR_CHALLENGE_INITIATION on FACTOR_SELECTED event")
    void testTransitionToAwaitingChallengeInitiation() {
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.PRIMARY_AUTH_SUCCESS).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.MFA_REQUIRED_SELECT_FACTOR).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.FACTOR_SELECTED).build())).blockFirst();
        assertThat(stateMachine.getState().getId()).isEqualTo(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
        verify(selectFactorAction, times(1)).execute(any());
    }

    @Test
    @DisplayName("FACTOR_VERIFICATION_PENDING -> FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION on FACTOR_VERIFICATION_FAILED when RetryLimitGuard is true")
    void testTransitionToAwaitingVerificationOnFailureWithRetry() {
        when(mfaSettings.getMaxRetryAttempts()).thenReturn(3);
        when(factorContext.getRetryCount()).thenReturn(1);
        when(factorContext.getCurrentProcessingFactor()).thenReturn(null);

        // 상태를 FACTOR_VERIFICATION_PENDING 까지 전이
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.PRIMARY_AUTH_SUCCESS).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.MFA_REQUIRED_SELECT_FACTOR).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.FACTOR_SELECTED).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.INITIATE_CHALLENGE).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.SUBMIT_FACTOR_CREDENTIAL).build())).blockFirst();

        assertThat(stateMachine.getState().getId()).isEqualTo(MfaState.FACTOR_VERIFICATION_PENDING);

        // 이벤트 실패 전달
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.FACTOR_VERIFICATION_FAILED).build())).blockFirst();

        assertThat(stateMachine.getState().getId()).isEqualTo(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        verify(handleFailureAction, times(1)).execute(any());
    }

    @Test
    @DisplayName("FACTOR_VERIFICATION_PENDING -> MFA_RETRY_LIMIT_EXCEEDED on FACTOR_VERIFICATION_FAILED when RetryLimitGuard is false")
    void testTransitionToRetryLimitExceededOnFailureWithoutRetry() {
        when(mfaSettings.getMaxRetryAttempts()).thenReturn(3);
        when(factorContext.getRetryCount()).thenReturn(3);
        when(factorContext.getCurrentProcessingFactor()).thenReturn(null);

        // 상태를 FACTOR_VERIFICATION_PENDING 까지 전이
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.PRIMARY_AUTH_SUCCESS).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.MFA_REQUIRED_SELECT_FACTOR).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.FACTOR_SELECTED).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.INITIATE_CHALLENGE).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.SUBMIT_FACTOR_CREDENTIAL).build())).blockFirst();

        // 이벤트 실패 전달
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.FACTOR_VERIFICATION_FAILED).build())).blockFirst();

        assertThat(stateMachine.getState().getId()).isEqualTo(MfaState.MFA_RETRY_LIMIT_EXCEEDED);
        verify(handleFailureAction, times(1)).execute(any());
    }

    @Test
    @DisplayName("FACTOR_VERIFICATION_COMPLETED -> ALL_FACTORS_COMPLETED on ALL_REQUIRED_FACTORS_COMPLETED when AllFactorsCompletedGuard is true")
    void testTransitionToAllFactorsCompleted() {
        when(factorContext.getUsername()).thenReturn("testuser");
        when(factorContext.getFlowTypeName()).thenReturn("mfa-flow");
        when(mfaPolicyProvider.getRequiredFactorCount("testuser", "mfa-flow")).thenReturn(1L);
        when(factorContext.getCompletedFactors()).thenReturn(Collections.singletonList(mock(AuthenticationStepConfig.class)));

        // FACTOR_VERIFICATION_PENDING 까지 전이
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.PRIMARY_AUTH_SUCCESS).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.MFA_REQUIRED_SELECT_FACTOR).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.FACTOR_SELECTED).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.INITIATE_CHALLENGE).build())).blockFirst();
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.SUBMIT_FACTOR_CREDENTIAL).build())).blockFirst();

        // 검증 성공 전달
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.FACTOR_VERIFIED_SUCCESS).build())).blockFirst();
        assertThat(stateMachine.getState().getId()).isEqualTo(MfaState.FACTOR_VERIFICATION_COMPLETED);

        // 모든 팩터 완료 전달
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED).build())).blockFirst();

        assertThat(stateMachine.getState().getId()).isEqualTo(MfaState.ALL_FACTORS_COMPLETED);
    }

    @Test
    @DisplayName("Invalid event transition should be ignored and state remained same")
    void testInvalidEventTransitionIgnored() {
        // NONE 상태에서는 SUBMIT_FACTOR_CREDENTIAL 이벤트를 보낼 수 없음
        stateMachine.sendEvent(Mono.just(MessageBuilder.withPayload(MfaEvent.SUBMIT_FACTOR_CREDENTIAL).build())).blockFirst();
        assertThat(stateMachine.getState().getId()).isEqualTo(MfaState.NONE);
    }
}
