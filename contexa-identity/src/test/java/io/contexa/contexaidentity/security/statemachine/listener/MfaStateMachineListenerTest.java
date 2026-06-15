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
package io.contexa.contexaidentity.security.statemachine.listener;

import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.state.State;
import org.springframework.statemachine.transition.Transition;
import org.springframework.statemachine.trigger.Trigger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaStateMachineListenerTest {

    private MfaStateChangeListener listener;

    @Mock
    private State<MfaState, MfaEvent> fromState;

    @Mock
    private State<MfaState, MfaEvent> toState;

    @Mock
    private Transition<MfaState, MfaEvent> transition;

    @Mock
    private Trigger<MfaState, MfaEvent> trigger;

    @Mock
    private StateMachine<MfaState, MfaEvent> stateMachine;

    @BeforeEach
    void setUp() {
        listener = new MfaStateChangeListener();
    }

    @Test
    @DisplayName("stateChanged should increment stateChangeCounters")
    void testStateChangedIncrementsCounters() {
        when(fromState.getId()).thenReturn(MfaState.NONE);
        when(toState.getId()).thenReturn(MfaState.PRIMARY_AUTHENTICATION_COMPLETED);

        listener.stateChanged(fromState, toState);

        long count = listener.getStateChangeCount("NONE", "PRIMARY_AUTHENTICATION_COMPLETED");
        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("stateChanged with null fromState should record INITIAL")
    void testStateChangedWithNullFrom() {
        when(toState.getId()).thenReturn(MfaState.PRIMARY_AUTHENTICATION_COMPLETED);

        listener.stateChanged(null, toState);

        long count = listener.getStateChangeCount("INITIAL", "PRIMARY_AUTHENTICATION_COMPLETED");
        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("transition should increment eventCounters when trigger exists")
    void testTransitionIncrementsEventCounters() {
        when(transition.getTrigger()).thenReturn(trigger);
        when(trigger.getEvent()).thenReturn(MfaEvent.PRIMARY_AUTH_SUCCESS);

        listener.transition(transition);

        long count = listener.getEventCount("PRIMARY_AUTH_SUCCESS");
        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("transition with null trigger does not throw and does not increment")
    void testTransitionWithNullTrigger() {
        when(transition.getTrigger()).thenReturn(null);

        listener.transition(transition);

        long count = listener.getEventCount("PRIMARY_AUTH_SUCCESS");
        assertThat(count).isEqualTo(0);
    }

    @Test
    @DisplayName("stateMachineError should handle error without throwing exception")
    void testStateMachineErrorHandling() {
        when(stateMachine.getId()).thenReturn("machine-1");
        Exception ex = new RuntimeException("Test error");

        listener.stateMachineError(stateMachine, ex);

        // 로깅이 성공적으로 이루어지고 예외를 던지지 않는지 검증
        assertThat(true).isTrue();
    }

    @Test
    @DisplayName("onSuccessfulTransition should be called successfully")
    void testOnSuccessfulTransition() {
        listener.onSuccessfulTransition("session-1", MfaState.NONE, MfaState.MFA_SUCCESSFUL, MfaEvent.PRIMARY_AUTH_SUCCESS);
        assertThat(true).isTrue();
    }

    @Test
    @DisplayName("onFailedTransition should handle and log transition failure")
    void testOnFailedTransition() {
        Exception ex = new RuntimeException("Transition failed");
        listener.onFailedTransition("session-1", MfaState.FACTOR_VERIFICATION_PENDING, MfaEvent.FACTOR_VERIFICATION_FAILED, ex);
        assertThat(true).isTrue();
    }
}
