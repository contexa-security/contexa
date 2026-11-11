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
import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexacommon.store.StoreGate;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.lang.Nullable;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;

import java.util.concurrent.TimeUnit;

/**
 * Distributed (Redis/Redisson) implementation of MFA StateMachine service.
 * Uses Redisson distributed locks for cross-node concurrency control.
 * <p>
 * A step that cannot take its lock because Redis does not answer is refused, as it always was: nothing goes on without the lock,
 * for the flow it would change is in the same Redis. The refusal does not make a request wait. The request that meets the outage
 * waits as long as Contexa's client for Redis lets it, and the gate of Redis (the one Contexa's other Redis state reports to)
 * learns of the outage from it; while the gate is down a request thread is refused at once, without trying Redisson, and the lock
 * it holds is left to its lease. A thread that serves no request keeps its waits.
 */
@Slf4j
public class MfaStateMachineServiceImpl extends AbstractMfaStateMachineService {

    private static final String LOCK_KEY_PREFIX = "mfa_lock:session:";
    private static final String REDIS_STATEMACHINE_KEY_PREFIX = "RedisRepositoryStateMachine:";

    private final RedissonClient redissonClient;
    @Nullable
    private final StoreGate redis;

    public MfaStateMachineServiceImpl(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            RedissonClient redissonClient,
            StateMachineProperties properties) {
        this(stateMachineFactory, stateMachinePersister, redissonClient, properties, null);
    }

    /** {@code redis}: the gate of the Redis the flows are in; without one a request thread waits for Redisson as any thread does. */
    public MfaStateMachineServiceImpl(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            RedissonClient redissonClient,
            StateMachineProperties properties,
            @Nullable StoreGate redis) {
        super(stateMachineFactory, stateMachinePersister, properties);
        this.redissonClient = redissonClient;
        this.redis = redis;
    }

    /**
     * Redis replaces a record in two commands (Spring Data deletes the key, then sets it) and this read takes no lock,
     * so a read between them finds no flow while the flow exists. The filters end a flow they do not find, so a flow that
     * looks gone is read again once the lock says no write is under way. A flow that cannot be read does not get here:
     * its read fails.
     */
    @Override
    public FactorContext getFactorContext(String sessionId) {
        FactorContext context = super.getFactorContext(sessionId);
        return context != null ? context : readBehindWrites(sessionId);
    }

    private FactorContext readBehindWrites(String sessionId) {
        boolean lockAcquired = false;
        try {
            lockAcquired = tryAcquireLock(sessionId, userRequestLockWaitTimeMillis(), TimeUnit.MILLISECONDS);
            return super.getFactorContext(sessionId);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new MfaStateMachineException("FactorContext retrieval interrupted: " + sessionId, e);
        } finally {
            if (lockAcquired) {
                releaseLock(sessionId);
            }
        }
    }

    @Override
    protected boolean tryAcquireLock(String sessionId, long waitTime, TimeUnit unit) throws InterruptedException {
        refuseWhileRedisIsDown();
        RLock lock = redissonClient.getLock(ApplicationNamespace.key(LOCK_KEY_PREFIX + sessionId));
        long leaseTime = Math.max(1, unit.convert(lockLeaseTimeSeconds(), TimeUnit.SECONDS));
        try {
            return lock.tryLock(waitTime, leaseTime, unit);
        } catch (RuntimeException failure) {
            reportToGate(failure);
            throw failure;
        }
    }

    @Override
    protected void releaseLock(String sessionId) {
        if (redisIsKnownDownForThisThread()) {
            return;
        }
        RLock lock = redissonClient.getLock(ApplicationNamespace.key(LOCK_KEY_PREFIX + sessionId));
        try {
            if (lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        } catch (RuntimeException failure) {
            reportToGate(failure);
            throw failure;
        }
    }

    @Override
    protected void onReleaseStateMachine(String sessionId) {
        refuseWhileRedisIsDown();
        String redisKey = ApplicationNamespace.key(REDIS_STATEMACHINE_KEY_PREFIX + sessionId);
        long deletedCount;
        try {
            deletedCount = redissonClient.getKeys().delete(redisKey);
        } catch (RuntimeException failure) {
            reportToGate(failure);
            throw failure;
        }
        if (deletedCount == 0) {
            log.debug("[MFA SM Service] [{}] StateMachine not found in Redis, skipping release.", sessionId);
        }
    }

    @Override
    protected void beforeSaveFactorContext(String sessionId) {
        refuseWhileRedisIsDown();
        String redisKey = ApplicationNamespace.key(REDIS_STATEMACHINE_KEY_PREFIX + sessionId);
        long keyExists;
        try {
            keyExists = redissonClient.getKeys().countExists(redisKey);
        } catch (RuntimeException failure) {
            reportToGate(failure);
            throw failure;
        }
        if (keyExists == 0) {
            log.debug("[MFA SM Service] [{}] StateMachine not found in Redis, proceeding with initialization", sessionId);
        }
    }

    /** A request thread whose Redis is known to be down gets what a request of Contexa's other Redis state gets: no wait. */
    private void refuseWhileRedisIsDown() {
        if (redisIsKnownDownForThisThread()) {
            throw redis.unavailable();
        }
    }

    private boolean redisIsKnownDownForThisThread() {
        return redis != null && redis.isDown() && RequestPathScope.onRequestThread();
    }

    /** The gate keeps what it takes for an outage of Redis (a Redis that cannot be reached or does not answer) and drops the rest. */
    private void reportToGate(RuntimeException failure) {
        if (redis != null) {
            redis.fail(failure);
        }
    }

    @Override
    protected void afterSaveFactorContext(String sessionId) {
        try {
            StateMachine<MfaState, MfaEvent> testMachine = acquireStateMachine(sessionId);
            try {
                stateMachinePersister.restore(testMachine, sessionId);
                FactorContext afterPersist = StateContextHelper.getFactorContext(testMachine);
                log.debug("[MFA SM Service] After persist verification [{}] - FactorContext: {}",
                        sessionId, afterPersist != null ? "exists (version " + afterPersist.getVersion() + ")" : "NULL");
            } finally {
                releaseStateMachineInstance(testMachine, sessionId);
            }
        } catch (Exception e) {
            log.warn("[MFA SM Service] Restore verification failed after persist [{}]", sessionId, e);
        }
    }
}
