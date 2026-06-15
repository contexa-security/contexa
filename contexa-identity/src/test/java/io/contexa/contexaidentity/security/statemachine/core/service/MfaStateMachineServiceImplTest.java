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
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.redisson.api.RKeys;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaStateMachineServiceImplTest {

    @Mock
    private StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;

    @Mock
    private StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;

    @Mock
    private RedissonClient redissonClient;

    @Mock
    private RLock lock;

    @Mock
    private RKeys keys;

    @Mock
    private StateMachine<MfaState, MfaEvent> stateMachine;

    private MfaStateMachineServiceImpl service;
    private StateMachineProperties properties;

    @BeforeEach
    void setUp() {
        properties = new StateMachineProperties();
        service = new MfaStateMachineServiceImpl(
                stateMachineFactory,
                stateMachinePersister,
                redissonClient,
                properties
        );

        when(redissonClient.getLock(anyString())).thenReturn(lock);
        when(redissonClient.getKeys()).thenReturn(keys);
        when(stateMachineFactory.getStateMachine(anyString())).thenReturn(stateMachine);
        when(stateMachine.startReactively()).thenReturn(reactor.core.publisher.Mono.empty());
        when(stateMachine.stopReactively()).thenReturn(reactor.core.publisher.Mono.empty());
    }

    @Test
    @DisplayName("tryAcquireLock should query Redisson and try Lock")
    void testTryAcquireLock() throws InterruptedException {
        when(lock.tryLock(eq(5L), eq(30L), eq(TimeUnit.SECONDS))).thenReturn(true);

        boolean result = service.tryAcquireLock("session-123", 5, TimeUnit.SECONDS);

        assertThat(result).isTrue();
        verify(redissonClient).getLock("mfa_lock:session:session-123");
        verify(lock).tryLock(5L, 30L, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("releaseLock should unlock if held by current thread")
    void testReleaseLockWhenHeld() {
        when(lock.isHeldByCurrentThread()).thenReturn(true);

        service.releaseLock("session-123");

        verify(lock).unlock();
    }

    @Test
    @DisplayName("releaseLock should not unlock if not held by current thread")
    void testReleaseLockWhenNotHeld() {
        when(lock.isHeldByCurrentThread()).thenReturn(false);

        service.releaseLock("session-123");

        verify(lock, never()).unlock();
    }

    @Test
    @DisplayName("onReleaseStateMachine should delete state machine key from Redis")
    void testOnReleaseStateMachine() {
        when(keys.delete("RedisRepositoryStateMachine:session-123")).thenReturn(1L);

        service.onReleaseStateMachine("session-123");

        verify(keys).delete("RedisRepositoryStateMachine:session-123");
    }

    @Test
    @DisplayName("beforeSaveFactorContext should log when key does not exist")
    void testBeforeSaveFactorContextLogs() {
        when(keys.countExists("RedisRepositoryStateMachine:session-123")).thenReturn(0L);

        service.beforeSaveFactorContext("session-123");

        verify(keys).countExists("RedisRepositoryStateMachine:session-123");
    }

    @Test
    @DisplayName("afterSaveFactorContext should restore and check factor context")
    void testAfterSaveFactorContext() throws Exception {
        FactorContext context = mock(FactorContext.class);
        when(context.getVersion()).thenReturn(5);

        try (MockedStatic<StateContextHelper> helperMock = mockStatic(StateContextHelper.class)) {
            helperMock.when(() -> StateContextHelper.getFactorContext(any(StateMachine.class))).thenReturn(context);

            service.afterSaveFactorContext("session-123");

            verify(stateMachinePersister).restore(stateMachine, "session-123");
        }
    }
}
