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
package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.core.persist.InMemoryStateMachinePersist;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateMachineEventResult;
import org.springframework.statemachine.access.StateMachineAccess;
import org.springframework.statemachine.access.StateMachineAccessor;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.statemachine.state.State;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.HashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The step of a sign-in waits for the state machine at most the transition time, and nothing but the request's own thread waits:
 * the wait of the request is the limit. A {@code timeout(Duration)} on the event's answer measured the same limit a second time on
 * Reactor's {@code parallel} scheduler, one the whole JVM shares, for every step of every sign-in.
 */
class MfaTransitionDeadlineTest {

    private static final String HOOK = "mfa-transition-deadline-test";
    private static final int TRANSITION_SECONDS = 1;

    @SuppressWarnings("unchecked")
    private final StateMachineFactory<MfaState, MfaEvent> factory = mock(StateMachineFactory.class);
    @SuppressWarnings("unchecked")
    private final StateMachinePersister<MfaState, MfaEvent, String> persister = mock(StateMachinePersister.class);
    @SuppressWarnings("unchecked")
    private final StateMachine<MfaState, MfaEvent> stateMachine = mock(StateMachine.class);
    @SuppressWarnings("unchecked")
    private final State<MfaState, MfaEvent> state = mock(State.class);
    private final AtomicInteger scheduledByTheRequest = new AtomicInteger();
    private StandaloneMfaStateMachineServiceImpl service;
    private Thread request;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        StateMachineProperties properties = new StateMachineProperties();
        properties.getMfa().setTransitionTimeoutSeconds(TRANSITION_SECONDS);
        service = new StandaloneMfaStateMachineServiceImpl(factory, persister, properties, mock(InMemoryStateMachinePersist.class));
        ExtendedState extendedState = mock(ExtendedState.class);
        StateMachineAccessor<MfaState, MfaEvent> accessor = mock(StateMachineAccessor.class);
        StateMachineAccess<MfaState, MfaEvent> access = mock(StateMachineAccess.class);
        when(factory.getStateMachine(anyString())).thenReturn(stateMachine);
        when(stateMachine.getExtendedState()).thenReturn(extendedState);
        when(extendedState.getVariables()).thenReturn(new HashMap<>());
        when(stateMachine.getStateMachineAccessor()).thenReturn(accessor);
        doAnswer(invocation -> {
            ((Consumer<StateMachineAccess<MfaState, MfaEvent>>) invocation.getArgument(0)).accept(access);
            return null;
        }).when(accessor).doWithAllRegions(any());
        when(access.resetStateMachineReactively(any())).thenReturn(Mono.empty());
        when(stateMachine.startReactively()).thenReturn(Mono.empty());
        when(stateMachine.stopReactively()).thenReturn(Mono.empty());
        when(stateMachine.getState()).thenReturn(state);
        when(state.getId()).thenReturn(MfaState.AWAITING_FACTOR_SELECTION);
        request = Thread.currentThread();
        // every task a scheduler of Reactor is given while the request's thread asks the state machine
        Schedulers.onScheduleHook(HOOK, task -> {
            if (Thread.currentThread() == request) {
                scheduledByTheRequest.incrementAndGet();
            }
            return task;
        });
    }

    @AfterEach
    void tearDown() {
        Schedulers.resetOnScheduleHook(HOOK);
    }

    @Test
    void aStateMachineThatDoesNotAnswerEndsTheStepAtTheTransitionTimeWithNoTimerOfReactor() {
        when(stateMachine.sendEvent(any(Mono.class))).thenReturn(Flux.never());
        FactorContext context = new FactorContext("session-1", mock(Authentication.class), MfaState.AWAITING_FACTOR_SELECTION, "test-flow");

        long started = System.nanoTime();
        boolean accepted = service.sendEvent(MfaEvent.FACTOR_SELECTED, context, mock(HttpServletRequest.class));
        long tookMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);

        // the step is refused as before, after the transition time and not later
        assertThat(accepted).isFalse();
        assertThat(context.getCurrentState()).isEqualTo(MfaState.AWAITING_FACTOR_SELECTION);
        assertThat(tookMs).isGreaterThanOrEqualTo(TRANSITION_SECONDS * 1000L - 50L).isLessThan(TRANSITION_SECONDS * 1000L + 800L);
        assertThat(scheduledByTheRequest).as("tasks the request handed to a scheduler of Reactor while it waited").hasValue(0);
    }

    @Test
    @SuppressWarnings("unchecked")
    void anAnsweredStepIsDecidedAsBeforeWithNoTimerOfReactor() {
        StateMachineEventResult<MfaState, MfaEvent> denied = mock(StateMachineEventResult.class);
        when(denied.getResultType()).thenReturn(StateMachineEventResult.ResultType.DENIED);
        when(stateMachine.sendEvent(any(Mono.class))).thenReturn(Flux.just(denied));
        FactorContext context = new FactorContext("session-1", mock(Authentication.class), MfaState.AWAITING_FACTOR_SELECTION, "test-flow");

        boolean accepted = service.sendEvent(MfaEvent.FACTOR_SELECTED, context, mock(HttpServletRequest.class));

        assertThat(accepted).isFalse();
        assertThat(scheduledByTheRequest).hasValue(0);
    }
}
