package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;

import java.util.concurrent.TimeUnit;

/**
 * Distributed (Redis/Redisson) implementation of MFA StateMachine service.
 * Uses Redisson distributed locks for cross-node concurrency control.
 */
@Slf4j
public class MfaStateMachineServiceImpl extends AbstractMfaStateMachineService {

    private static final String LOCK_KEY_PREFIX = "mfa_lock:session:";
    private static final String REDIS_STATEMACHINE_KEY_PREFIX = "RedisRepositoryStateMachine:";

    private final RedissonClient redissonClient;

    public MfaStateMachineServiceImpl(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            RedissonClient redissonClient,
            StateMachineProperties properties) {
        super(stateMachineFactory, stateMachinePersister, properties);
        this.redissonClient = redissonClient;
    }

    @Override
    protected boolean tryAcquireLock(String sessionId, long waitTime, TimeUnit unit) throws InterruptedException {
        RLock lock = redissonClient.getLock(LOCK_KEY_PREFIX + sessionId);
        return lock.tryLock(waitTime, LOCK_LEASE_TIME_SECONDS, unit);
    }

    @Override
    protected void releaseLock(String sessionId) {
        RLock lock = redissonClient.getLock(LOCK_KEY_PREFIX + sessionId);
        if (lock.isHeldByCurrentThread()) {
            lock.unlock();
        }
    }

    @Override
    protected void onReleaseStateMachine(String sessionId) {
        String redisKey = REDIS_STATEMACHINE_KEY_PREFIX + sessionId;
        long deletedCount = redissonClient.getKeys().delete(redisKey);
        if (deletedCount == 0) {
            log.error("[MFA SM Service] [{}] StateMachine not found in Redis, skipping release.", sessionId);
        }
    }

    @Override
    protected void beforeSaveFactorContext(String sessionId) {
        String redisKey = REDIS_STATEMACHINE_KEY_PREFIX + sessionId;
        long keyExists = redissonClient.getKeys().countExists(redisKey);
        if (keyExists == 0) {
            log.error("[MFA SM Service] [{}] StateMachine not found in Redis, proceeding with initialization", sessionId);
        }
    }

    @Override
    protected void afterSaveFactorContext(String sessionId) {
        try {
            StateMachine<MfaState, MfaEvent> testMachine = acquireStateMachine(sessionId);
            try {
                stateMachinePersister.restore(testMachine, sessionId);
                FactorContext afterPersist = StateContextHelper.getFactorContext(testMachine);
                log.error("[MFA SM Service] After persist verification [{}] - FactorContext: {}",
                        sessionId, afterPersist != null ? "exists (version " + afterPersist.getVersion() + ")" : "NULL");
            } finally {
                releaseStateMachineInstance(testMachine, sessionId);
            }
        } catch (Exception e) {
            log.error("[MFA SM Service] Restore verification failed after persist [{}]", sessionId, e);
        }
    }
}
