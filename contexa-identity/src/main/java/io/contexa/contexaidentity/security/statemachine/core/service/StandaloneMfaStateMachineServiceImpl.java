package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
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

    public StandaloneMfaStateMachineServiceImpl(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            StateMachineProperties properties) {
        super(stateMachineFactory, stateMachinePersister, properties);
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
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        locks.remove(sessionId);
    }
}
