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

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.redisson.api.RKeys;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The lock of a flow and the key of its stored state are a named application's own. */
class MfaStateMachineServiceImplApplicationTest {

    @SuppressWarnings("unchecked")
    private final StateMachineFactory<MfaState, MfaEvent> factory = mock(StateMachineFactory.class);
    @SuppressWarnings("unchecked")
    private final StateMachinePersister<MfaState, MfaEvent, String> persister = mock(StateMachinePersister.class);
    private final RedissonClient redisson = mock(RedissonClient.class);
    private final RLock lock = mock(RLock.class);
    private final RKeys keys = mock(RKeys.class);
    private final MfaStateMachineServiceImpl service =
            new MfaStateMachineServiceImpl(factory, persister, redisson, new StateMachineProperties());

    @Test
    @DisplayName("the lock of a flow is named behind the name of the application, so that another application's flow of the same id is not this one")
    void theLockIsBehindTheName() throws InterruptedException {
        when(redisson.getLock(anyString())).thenReturn(lock);
        when(lock.tryLock(5L, 30L, TimeUnit.SECONDS)).thenReturn(true);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            assertThat(service.tryAcquireLock("session-123", 5, TimeUnit.SECONDS)).isTrue();
        }

        verify(redisson).getLock("ctxa:shop:mfa_lock:session:session-123");
    }

    @Test
    @DisplayName("the stored state of a flow is read and removed under the key the repository stores it under, behind the name")
    void theStoredStateIsBehindTheName() {
        when(redisson.getKeys()).thenReturn(keys);
        when(keys.delete("ctxa:shop:RedisRepositoryStateMachine:session-123")).thenReturn(1L);
        when(keys.countExists("ctxa:shop:RedisRepositoryStateMachine:session-123")).thenReturn(1L);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            service.onReleaseStateMachine("session-123");
            service.beforeSaveFactorContext("session-123");
        }

        verify(keys).delete("ctxa:shop:RedisRepositoryStateMachine:session-123");
        verify(keys).countExists("ctxa:shop:RedisRepositoryStateMachine:session-123");
    }
}
