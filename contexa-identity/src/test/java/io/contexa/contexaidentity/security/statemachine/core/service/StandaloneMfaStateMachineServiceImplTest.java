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
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.messaging.Message;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateMachineEventResult;
import org.springframework.statemachine.access.StateMachineAccess;
import org.springframework.statemachine.access.StateMachineAccessor;
import org.springframework.statemachine.config.StateMachineFactory;
import java.lang.reflect.Method;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.statemachine.state.State;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class StandaloneMfaStateMachineServiceImplTest {

    @Mock
    private StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;

    @Mock
    private StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;

    @Mock
    private InMemoryStateMachinePersist inMemoryStateMachinePersist;

    @Mock
    private StateMachine<MfaState, MfaEvent> stateMachine;

    @Mock
    private ExtendedState extendedState;

    @Mock
    private StateMachineAccess<MfaState, MfaEvent> stateMachineAccessor;

    @Mock
    private StateMachineAccessor<MfaState, MfaEvent> accessorMock;

    @Mock
    private State<MfaState, MfaEvent> mockState;

    @Mock
    private Authentication authentication;

    @Mock
    private HttpServletRequest request;

    private StandaloneMfaStateMachineServiceImpl service;
    private StateMachineProperties properties;

    @BeforeEach
    void setUp() {
        properties = new StateMachineProperties();
        properties.getMfa().setTransitionTimeoutSeconds(5);
        service = new StandaloneMfaStateMachineServiceImpl(
                stateMachineFactory,
                stateMachinePersister,
                properties,
                inMemoryStateMachinePersist
        );

        when(stateMachineFactory.getStateMachine(anyString())).thenReturn(stateMachine);
        when(stateMachine.getExtendedState()).thenReturn(extendedState);
        when(extendedState.getVariables()).thenReturn(new HashMap<>());
        when(stateMachine.getStateMachineAccessor()).thenReturn(accessorMock);
        
        // doWithAllRegions 모킹
        doAnswer(invocation -> {
            Object function = invocation.getArgument(0);
            try {
                Method method = null;
                for (Method m : function.getClass().getMethods()) {
                    if (m.getName().equals("apply") || m.getName().equals("accept")) {
                        method = m;
                        break;
                    }
                }
                if (method != null) {
                    method.setAccessible(true);
                    method.invoke(function, stateMachineAccessor);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return null;
        }).when(accessorMock).doWithAllRegions(any());

        when(stateMachineAccessor.resetStateMachineReactively(any())).thenReturn(Mono.empty());
        when(stateMachine.startReactively()).thenReturn(Mono.empty());
        when(stateMachine.stopReactively()).thenReturn(Mono.empty());
    }

    @Test
    @DisplayName("releaseStateMachine should delete persisted in-memory state")
    void releaseStateMachineDeletesPersistedState() {
        service.releaseStateMachine("session-1");
        verify(inMemoryStateMachinePersist).delete("session-1");
    }

    @Test
    @DisplayName("initializeStateMachine should acquire lock, initialize and persist State Machine")
    void initializeStateMachineSuccessfully() throws Exception {
        FactorContext context = new FactorContext("session-1", authentication, MfaState.NONE, "test-flow");

        service.initializeStateMachine(context, request);

        verify(stateMachineFactory).getStateMachine("session-1");
        verify(accessorMock).doWithAllRegions(any());
        verify(stateMachinePersister).persist(stateMachine, "session-1");
    }

    @Test
    @DisplayName("initializeStateMachine throws exception when failed to acquire lock")
    void initializeStateMachineThrowsExceptionOnLockTimeout() throws Exception {
        FactorContext context = new FactorContext("session-1", authentication, MfaState.NONE, "test-flow");

        // 강제로 다른 스레드에서 락을 획득하게 만듦
        service.tryAcquireLock("session-1", 1, TimeUnit.SECONDS);

        // 짧은 락 획득 타임아웃을 강제하는 등, 여기서는 직접 service.tryAcquireLock을 수행했으므로, 
        // initializeStateMachine 호출 시 동일 세션 락 획득에 실패하거나 데드락 시나리오가 됨
        // 테스트 스레드에서 바로 검증하기 위해 리액티브 타임아웃 등을 고려한 예외 발생 검증
        StandaloneMfaStateMachineServiceImpl customService = new StandaloneMfaStateMachineServiceImpl(
                stateMachineFactory,
                stateMachinePersister,
                properties,
                inMemoryStateMachinePersist
        ) {
            @Override
            protected boolean tryAcquireLock(String sessionId, long waitTime, TimeUnit unit) {
                return false; // 무조건 락 획득 실패
            }
        };

        assertThatThrownBy(() -> customService.initializeStateMachine(context, request))
                .isInstanceOf(AbstractMfaStateMachineService.MfaStateMachineException.class)
                .hasMessageContaining("Failed to acquire lock for State Machine initialization");
    }

    @Test
    @DisplayName("sendEvent successfully transitions state and synchronizes context")
    void sendEventSuccessfully() throws Exception {
        FactorContext context = new FactorContext("session-1", authentication, MfaState.NONE, "test-flow");
        when(stateMachine.getState()).thenReturn(mockState);
        when(mockState.getId()).thenReturn(MfaState.AWAITING_FACTOR_SELECTION);

        StateMachineEventResult<MfaState, MfaEvent> eventResult = mock(StateMachineEventResult.class);
        when(eventResult.getResultType()).thenReturn(StateMachineEventResult.ResultType.ACCEPTED);
        when(stateMachine.sendEvent(any(Mono.class))).thenReturn(Flux.just(eventResult));

        try (MockedStatic<StateContextHelper> helperMock = mockStatic(StateContextHelper.class)) {
            FactorContext contextFromSm = new FactorContext("session-1", authentication, MfaState.AWAITING_FACTOR_SELECTION, "test-flow");
            contextFromSm.setVersion(2);
            helperMock.when(() -> StateContextHelper.getFactorContext(any(StateMachine.class))).thenReturn(contextFromSm);

            boolean result = service.sendEvent(MfaEvent.PRIMARY_AUTH_SUCCESS, context, request);

            assertThat(result).isTrue();
            assertThat(context.getCurrentState()).isEqualTo(MfaState.AWAITING_FACTOR_SELECTION);
            assertThat(context.getVersion()).isEqualTo(2);
            verify(stateMachinePersister).persist(stateMachine, "session-1");
        }
    }

    @Test
    @DisplayName("sendEvent returns false when event is rejected")
    void sendEventRejected() {
        FactorContext context = new FactorContext("session-1", authentication, MfaState.NONE, "test-flow");
        when(stateMachine.getState()).thenReturn(mockState);
        when(mockState.getId()).thenReturn(MfaState.NONE);

        StateMachineEventResult<MfaState, MfaEvent> eventResult = mock(StateMachineEventResult.class);
        when(eventResult.getResultType()).thenReturn(StateMachineEventResult.ResultType.DENIED);
        when(stateMachine.sendEvent(any(Mono.class))).thenReturn(Flux.just(eventResult));

        boolean result = service.sendEvent(MfaEvent.SUBMIT_FACTOR_CREDENTIAL, context, request);

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("getFactorContext returns retrieved context from State Machine")
    void getFactorContextRetrieval() {
        FactorContext context = new FactorContext("session-1", authentication, MfaState.NONE, "test-flow");
        try (MockedStatic<StateContextHelper> helperMock = mockStatic(StateContextHelper.class)) {
            helperMock.when(() -> StateContextHelper.getFactorContext(any(StateMachine.class))).thenReturn(context);

            FactorContext retrieved = service.getFactorContext("session-1");

            assertThat(retrieved).isSameAs(context);
        }
    }

    @Test
    @DisplayName("saveFactorContext successfully restores and persists state")
    void saveFactorContextSuccessfully() throws Exception {
        FactorContext context = new FactorContext("session-1", authentication, MfaState.AWAITING_FACTOR_SELECTION, "test-flow");

        service.saveFactorContext(context);

        verify(stateMachinePersister).restore(stateMachine, "session-1");
        verify(stateMachinePersister).persist(stateMachine, "session-1");
    }

    @Test
    @DisplayName("updateStateOnly forces target state and persists")
    void updateStateOnlySuccessfully() throws Exception {
        FactorContext context = new FactorContext("session-1", authentication, MfaState.NONE, "test-flow");
        try (MockedStatic<StateContextHelper> helperMock = mockStatic(StateContextHelper.class)) {
            helperMock.when(() -> StateContextHelper.getFactorContext(any(StateMachine.class))).thenReturn(context);

            boolean result = service.updateStateOnly("session-1", MfaState.MFA_SUCCESSFUL);

            assertThat(result).isTrue();
            assertThat(context.getCurrentState()).isEqualTo(MfaState.MFA_SUCCESSFUL);
            verify(stateMachinePersister).persist(stateMachine, "session-1");
        }
    }

    @Test
    @DisplayName("Locks prevent concurrent access to the same session")
    void locksPreventConcurrentAccess() throws Exception {
        CountDownLatch latch1 = new CountDownLatch(1);
        CountDownLatch latch2 = new CountDownLatch(1);
        AtomicBoolean lockAcquiredByThread2 = new AtomicBoolean(false);

        ExecutorService executor = Executors.newFixedThreadPool(2);

        // 스레드 1: 락 획득 후 대기
        executor.submit(() -> {
            try {
                boolean locked = service.tryAcquireLock("session-lock", 1, TimeUnit.SECONDS);
                if (locked) {
                    latch1.countDown(); // 락 획득 성공을 스레드 2에게 알림
                    latch2.await();     // 스레드 2가 락 시도를 끝낼 때까지 대기
                    service.releaseLock("session-lock");
                }
            } catch (Exception e) {
                Thread.currentThread().interrupt();
            }
        });

        // 스레드 2: 스레드 1이 락을 해제하기 전에 락 시도 (실패해야 함)
        executor.submit(() -> {
            try {
                latch1.await(); // 스레드 1이 락을 잡을 때까지 대기
                boolean locked = service.tryAcquireLock("session-lock", 200, TimeUnit.MILLISECONDS);
                lockAcquiredByThread2.set(locked);
                latch2.countDown();
            } catch (Exception e) {
                Thread.currentThread().interrupt();
            }
        });

        executor.shutdown();
        executor.awaitTermination(3, TimeUnit.SECONDS);

        assertThat(lockAcquiredByThread2.get()).isFalse();
    }
}

