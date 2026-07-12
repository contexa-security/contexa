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

import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.core.persist.InMemoryStateMachinePersist;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Standalone (in-memory) implementation of MFA StateMachine service.
 * Uses local ReentrantLock for single-node concurrency control.
 */
public class StandaloneMfaStateMachineServiceImpl extends AbstractMfaStateMachineService {

    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();
    private final InMemoryStateMachinePersist inMemoryStateMachinePersist;

    public StandaloneMfaStateMachineServiceImpl(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            StateMachineProperties properties,
            InMemoryStateMachinePersist inMemoryStateMachinePersist) {
        super(stateMachineFactory, stateMachinePersister, properties);
        this.inMemoryStateMachinePersist = inMemoryStateMachinePersist;
    }

    @Override
    protected boolean tryAcquireLock(String sessionId, long waitTime, TimeUnit unit) throws InterruptedException {
        ReentrantLock lock = locks.computeIfAbsent(sessionId, k -> new ReentrantLock());
        return lock.tryLock(waitTime, unit);
    }

    @Override
    protected void releaseLock(String sessionId) {
        ReentrantLock lock = locks.get(sessionId);
        if (lock != null) {
            lock.unlock();
        }
    }

    @Override
    protected void onReleaseStateMachine(String sessionId) {
        locks.remove(sessionId);
        inMemoryStateMachinePersist.delete(sessionId);
    }
}
