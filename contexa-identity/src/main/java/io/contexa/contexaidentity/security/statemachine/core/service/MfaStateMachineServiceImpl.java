package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.messaging.Message;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachineEventResult;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
public class MfaStateMachineServiceImpl implements MfaStateMachineService {

    private final StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;
    private final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;
    private final RedissonClient redissonClient;
    private final StateMachineProperties properties;

    public MfaStateMachineServiceImpl(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            RedissonClient redissonClient,
            StateMachineProperties properties) {
        this.stateMachineFactory = stateMachineFactory;
        this.stateMachinePersister = stateMachinePersister;
        this.redissonClient = redissonClient;
        this.properties = properties;
    }

    private static final long LOCK_WAIT_TIME_SECONDS = 10;
    private static final long LOCK_LEASE_TIME_SECONDS = 30;
    private static final MfaState FALLBACK_INITIAL_MFA_STATE = MfaState.NONE;
    private static final String REDIS_STATEMACHINE_KEY_PREFIX = "RedisRepositoryStateMachine:";

    private String getLockKey(String sessionId) {
        return "mfa_lock:session:" + sessionId;
    }

    private StateMachine<MfaState, MfaEvent> acquireStateMachine(String sessionId) {
        StateMachine<MfaState, MfaEvent> sm = stateMachineFactory.getStateMachine(sessionId);
        return sm;
    }

    private void releaseStateMachineInstance(StateMachine<MfaState, MfaEvent> sm, String sessionId) {
        if (sm != null) {
            try {
                sm.stopReactively().block(Duration.ofSeconds(5));
            } catch (Exception e) {
                log.error("[MFA SM Service] [{}] Error during StateMachine cleanup (ignored): {}", sessionId, e.getMessage());
            }
        }
    }

    private StateMachine<MfaState, MfaEvent> getAndPrepareStateMachine(String machineId, MfaState initialStateIfNotRestored, FactorContext initialFactorContextForReset) {
        StateMachine<MfaState, MfaEvent> stateMachine = acquireStateMachine(machineId);
        try {
            stateMachinePersister.restore(stateMachine, machineId);

            ExtendedState restoredExtendedState = stateMachine.getExtendedState();
            FactorContext restoredContext = StateContextHelper.getFactorContext(stateMachine);
            log.error("[VERIFY-3] Right after restore() [{}] - ExtendedState variable count: {}, FactorContext: {}",
                    machineId, restoredExtendedState.getVariables().size(),
                    restoredContext != null ? "exists (version " + restoredContext.getVersion() + ")" : "NULL");

            if (stateMachine.getState() == null || stateMachine.getState().getId() == null) {
                log.error("[MFA SM Service] [{}] State is null after restore. Resetting to initialState: {}", machineId, initialStateIfNotRestored);
                log.error("[VERIFY-3] State is null but FactorContext [{}]: {}",
                        machineId, restoredContext != null ? "exists (version " + restoredContext.getVersion() + ")" : "NULL");
                updateAndStartStateMachine(stateMachine, machineId, initialStateIfNotRestored, initialFactorContextForReset);
            } else {
                try {
                    stateMachine.startReactively().block();
                } catch (Exception startEx) {
                    log.error("[MFA SM Service] [{}] StateMachine start after restore failed (may already be running): {}", machineId, startEx.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] StateMachine restore failed or new session. Setting initial state: {}. Error: {}", machineId, initialStateIfNotRestored, e.getMessage());
            updateAndStartStateMachine(stateMachine, machineId, initialStateIfNotRestored, initialFactorContextForReset);
        }
        return stateMachine;
    }

    private void updateAndStartStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String machineId, MfaState targetState, FactorContext factorContext) {
        if (stateMachine.getState() != null) {
            stateMachine.stopReactively().block();
        }

        ExtendedState extendedState = stateMachine.getExtendedState();

        if (factorContext != null) {
            StateContextHelper.setFactorContext(extendedState, factorContext);
        }

        StateMachineContext<MfaState, MfaEvent> newContext = new DefaultStateMachineContext<>(
                targetState, null, null, extendedState, null, machineId);

        stateMachine.getStateMachineAccessor()
                .doWithAllRegions(access -> access.resetStateMachineReactively(newContext).block());

        stateMachine.startReactively().block();
    }

    private void resetAndStartStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String machineId, MfaState targetState, FactorContext factorContext) {
        if (stateMachine.getState() != null) {
            stateMachine.stopReactively().block();
        }

        ExtendedState extendedState = stateMachine.getExtendedState();
        extendedState.getVariables().clear();

        if (factorContext != null) {
            StateContextHelper.setFactorContext(extendedState, factorContext);
        }

        StateMachineContext<MfaState, MfaEvent> newContext = new DefaultStateMachineContext<>(
                targetState, null, null, extendedState, null, machineId);

        stateMachine.getStateMachineAccessor()
                .doWithAllRegions(access -> access.resetStateMachineReactively(newContext).block());
        stateMachine.startReactively().block();

        ExtendedState finalExtendedState = stateMachine.getExtendedState();
        FactorContext finalContext = StateContextHelper.getFactorContext(stateMachine);
        log.error("[VERIFY-1] After resetAndStartStateMachine completion [{}] - ExtendedState variable count: {}, FactorContext: {}",
                machineId, finalExtendedState.getVariables().size(),
                finalContext != null ? "exists (version " + finalContext.getVersion() + ")" : "NULL");
    }

    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);

            if (!lockAcquired) {
                log.error("[MFA SM Service] [{}] Failed to acquire lock for SM initialization.", sessionId);
                throw new MfaStateMachineException("Failed to acquire lock for State Machine initialization: " + sessionId);
            }

            stateMachine = acquireStateMachine(sessionId);
            resetAndStartStateMachine(stateMachine, sessionId, context.getCurrentState(), context);

            context.incrementVersion();

            StateContextHelper.setFactorContext(stateMachine, context);
            persistStateMachine(stateMachine, sessionId);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] Interrupt occurred during SM initialization.", sessionId, e);
            throw new MfaStateMachineException("State Machine initialization interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during SM initialization.", sessionId, e);
            throw new MfaStateMachineException("Error during State Machine initialization for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
    }

    @Override
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        return sendEvent(event, context, request, null);
    }

    @Override
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request, Map<String, Object> additionalHeaders) {
        String sessionId = context.getMfaSessionId();
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;
        Result eventProcessingResult;

        try {
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[MFA SM Service] [{}] Failed to acquire lock for event ({}) processing.", sessionId, event);
                return false;
            }

            stateMachine = getAndPrepareStateMachine(sessionId, context.getCurrentState(), context);

            FactorContext restoredFc = StateContextHelper.getFactorContext(stateMachine);
            log.error("[SM-RESEND-1] After restore: SM internal retryCount={}, external retryCount={}, event={}, sessionId={}",
                    restoredFc != null ? restoredFc.getRetryCount() : "null",
                    context.getRetryCount(), event, sessionId);

            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context);

            Message<MfaEvent> message = createEventMessage(event, context, request, additionalHeaders);
            eventProcessingResult = sendEventInternal(stateMachine, message, context);

            if (eventProcessingResult.eventAccepted()) {
            } else {
                log.error("[MFA SM Service] [{}] Event ({}) not accepted in current SM state ({}).", sessionId, event, eventProcessingResult.smCurrentStateAfterEvent());
            }

            synchronizeExternalContext(context, eventProcessingResult.contextFromSmAfterEvent(), eventProcessingResult.smCurrentStateAfterEvent());
            StateContextHelper.setFactorContext(stateMachine, context);
            persistStateMachine(stateMachine, sessionId);

            return eventProcessingResult.eventAccepted();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] Interrupt occurred during event ({}) processing.", sessionId, event, e);
            throw new MfaStateMachineException("MFA event processing interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during event ({}) processing.", sessionId, event, e);
            throw new MfaStateMachineException("Error during MFA event processing for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
    }

    private Result sendEventInternal(StateMachine<MfaState, MfaEvent> stateMachine, Message<MfaEvent> message, FactorContext originalExternalContext) {
        String sessionId = originalExternalContext.getMfaSessionId();
        MfaEvent event = message.getPayload();
        MfaState currentState = stateMachine.getState() != null ? stateMachine.getState().getId() : null;

        int timeoutSeconds = properties.getMfa().getTransitionTimeoutSeconds() != null ?
                properties.getMfa().getTransitionTimeoutSeconds() : 10;

        log.error("[SM Internal] sendEventInternal START - Event: {}, CurrentState: {}, Session: {}", event, currentState, sessionId);

        Boolean accepted;
        try {
            accepted = stateMachine.sendEvent(Mono.just(message))
                    .doOnNext(result -> log.error("[SM Internal] Event result received - ResultType: {}, Session: {}",
                            result.getResultType(), sessionId))
                    .doOnError(error -> log.error("[SM Internal] Event processing error - Event: {}, Session: {}, Error: {}",
                            event, sessionId, error.getMessage(), error))
                    .doOnComplete(() -> log.error("[SM Internal] Reactive Stream completed - Event: {}, Session: {}",
                            event, sessionId))
                    .map(result -> result.getResultType() == StateMachineEventResult.ResultType.ACCEPTED)
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .doOnNext(isAccepted -> log.error("[SM Internal] Event accepted: {} - Event: {}, Session: {}",
                            isAccepted, event, sessionId))
                    .blockFirst(Duration.ofSeconds(timeoutSeconds + 1));
        } catch (Exception e) {
            log.error("[SM Internal] Exception during sendEvent - Event: {}, State: {}, Session: {}, Exception: {}",
                    event, currentState, sessionId, e.getMessage(), e);

            MfaState fallbackState = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
            FactorContext fallbackContext = StateContextHelper.getFactorContext(stateMachine);
            return new Result(false, fallbackState, fallbackContext != null ? fallbackContext : originalExternalContext);
        }
        log.error("[SM Internal] blockFirst() returned - accepted: {}, Event: {}, Session: {}",
                accepted, event, sessionId);

        if (accepted == null) {
            log.error("[SM Internal] Event processing timeout - Event: {}, State: {}, Session: {}, Timeout: {}s",
                    event, currentState, sessionId, timeoutSeconds);

            MfaState fallbackState = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
            FactorContext fallbackContext = StateContextHelper.getFactorContext(stateMachine);

            return new Result(false, fallbackState, fallbackContext != null ? fallbackContext : originalExternalContext);
        }

        boolean eventAccepted = Boolean.TRUE.equals(accepted);
        MfaState smStateAfterEvent = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
        FactorContext contextFromSmAfterEvent = StateContextHelper.getFactorContext(stateMachine);

        log.error("[SM Internal] sendEventInternal END - EventAccepted: {}, StateAfter: {}, Session: {}",
                eventAccepted, smStateAfterEvent, sessionId);

        if (contextFromSmAfterEvent != null) {
            Object factorsObj = contextFromSmAfterEvent.getAttribute("availableFactors");

            if (factorsObj == null) {
                log.error("[sendEventInternal] availableFactors is NULL in contextFromSm for session: {}",
                        originalExternalContext.getMfaSessionId());
            }
        } else {
            log.error("[sendEventInternal] contextFromSm is NULL for session: {}",
                    originalExternalContext.getMfaSessionId());
        }

        return new Result(eventAccepted, smStateAfterEvent, contextFromSmAfterEvent);
    }

    private void synchronizeExternalContext(FactorContext externalContext, FactorContext contextFromSm, MfaState smActualState) {
        if (externalContext == null) {
            log.error("[MFA SM Service] External context is null, skipping synchronization");
            return;
        }

        if (contextFromSm != null) {
            externalContext.changeState(smActualState);
            externalContext.setVersion(contextFromSm.getVersion());

            if (contextFromSm.getAttributes() != null) {
                contextFromSm.getAttributes().forEach((key, value) -> {

                    Object copiedValue = deepCopyIfNeeded(key, value);
                    externalContext.setAttribute(key, copiedValue);
                    if ("availableFactors".equals(key)) {
                    }
                });
            }

            externalContext.setCurrentProcessingFactor(contextFromSm.getCurrentProcessingFactor());
            externalContext.setCurrentStepId(contextFromSm.getCurrentStepId());
            externalContext.setMfaRequiredAsPerPolicy(contextFromSm.isMfaRequiredAsPerPolicy());
            log.error("[SM-SYNC] retryCount sync: external={} -> fromSm={}, sessionId={}",
                    externalContext.getRetryCount(), contextFromSm.getRetryCount(), externalContext.getMfaSessionId());
            externalContext.setRetryCount(contextFromSm.getRetryCount());
            externalContext.setLastError(contextFromSm.getLastError());

            if (contextFromSm.getLastActivityTimestamp() != null) {
                externalContext.updateLastActivityTimestamp();
            }
        } else {

            log.error("[MFA SM Service] [{}] FactorContext not found inside SM. Only updating external context state to actual SM state.", externalContext.getMfaSessionId());
            externalContext.changeState(smActualState);
        }
    }

    private void persistStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String sessionId) throws Exception {
        stateMachinePersister.persist(stateMachine, sessionId);
    }

    @Override
    public FactorContext getFactorContext(String sessionId) {
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;
        try {
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS / 2, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[MFA SM Service] [{}] Failed to acquire lock for FactorContext retrieval. Returning null.", sessionId);
                return null;
            }
            stateMachine = getAndPrepareStateMachine(sessionId, FALLBACK_INITIAL_MFA_STATE, null);
            return StateContextHelper.getFactorContext(stateMachine);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] Interrupt occurred during FactorContext retrieval.", sessionId, e);
            throw new MfaStateMachineException("Get FactorContext interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during FactorContext retrieval.", sessionId, e);
            throw new MfaStateMachineException("Error during getFactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
    }

    @Override
    public void saveFactorContext(FactorContext context) {
        String sessionId = context.getMfaSessionId();
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[MFA SM Service] [{}] Failed to acquire lock for FactorContext save.", sessionId);
                throw new MfaStateMachineException("Failed to acquire lock for saving FactorContext: " + sessionId);
            }

            String redisKey = REDIS_STATEMACHINE_KEY_PREFIX + sessionId;
            long keyExists = redissonClient.getKeys().countExists(redisKey);

            if (keyExists == 0) {
                log.error("[MFA SM Service] [{}] StateMachine not found in Redis, proceeding with initialization", sessionId);
            }

            stateMachine = acquireStateMachine(sessionId);

            boolean restored = false;
            try {
                stateMachinePersister.restore(stateMachine, sessionId);
                if (stateMachine.getState() != null && stateMachine.getState().getId() != null) {
                    restored = true;
                } else {
                    log.error("[MFA SM Service] [{}] State is null after SM restore. Starting fresh.", sessionId);
                }
            } catch (Exception e) {
                log.error("[MFA SM Service] [{}] SM restore failed. Starting fresh. Error: {}", sessionId, e.getMessage());
            }

            if (!restored) {
                stateMachine.startReactively().block();
            }

            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context);

            FactorContext beforePersist = StateContextHelper.getFactorContext(stateMachine);
            log.error("[VERIFY-2] Before persistStateMachine call [{}] - FactorContext: {}",
                    sessionId, beforePersist != null ? "exists (version " + beforePersist.getVersion() + ")" : "NULL");

            persistStateMachine(stateMachine, sessionId);

            try {
                StateMachine<MfaState, MfaEvent> testMachine = acquireStateMachine(sessionId);
                try {
                    stateMachinePersister.restore(testMachine, sessionId);
                    FactorContext afterPersist = StateContextHelper.getFactorContext(testMachine);
                    log.error("[VERIFY-2] After persistStateMachine restore [{}] - FactorContext: {}",
                            sessionId, afterPersist != null ? "exists (version " + afterPersist.getVersion() + ")" : "NULL");
                } finally {
                    releaseStateMachineInstance(testMachine, sessionId);
                }
            } catch (Exception e) {
                log.error("[VERIFY-2] Restore failed after persistStateMachine [{}]", sessionId, e);
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] Interrupt occurred during FactorContext save.", sessionId, e);
            throw new MfaStateMachineException("Saving FactorContext interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during FactorContext save.", sessionId, e);
            throw new MfaStateMachineException("Error during saving FactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
    }

    @Override
    public MfaState getCurrentState(String sessionId) {
        FactorContext context = getFactorContext(sessionId);
        if (context != null) {
            return context.getCurrentState();
        }
        log.error("[MFA SM Service] [{}] Current state retrieval failed: FactorContext not found. Returning NONE.", sessionId);
        return MfaState.NONE;
    }

    @Override
    public boolean updateStateOnly(String sessionId, MfaState newState) {
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[MFA SM Service] [{}] Failed to acquire lock for state-only update.", sessionId);
                return false;
            }

            stateMachine = getAndPrepareStateMachine(sessionId, newState, null);
            FactorContext factorContext = StateContextHelper.getFactorContext(stateMachine);

            if (factorContext == null) {
                log.error("[MFA SM Service] [{}] State-only update failed: FactorContext not found. Creating new FactorContext and setting state.", sessionId);

                Authentication currentAuth = stateMachine.getExtendedState().get("authentication", Authentication.class);
                factorContext = new FactorContext(sessionId, currentAuth, newState, null);
            }

            factorContext.changeState(newState);
            updateAndStartStateMachine(stateMachine, sessionId, newState, factorContext);
            persistStateMachine(stateMachine, sessionId);

            return true;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] Interrupt occurred during state-only update.", sessionId, e);
            throw new MfaStateMachineException("State-only update interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during state-only update.", sessionId, e);
            throw new MfaStateMachineException("Error during state-only update for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;

        try {
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);

            if (!lockAcquired) {
                log.error("[MFA SM Service] [{}] Failed to acquire lock for SM release. Timeout.", sessionId);
                return;
            }

            String redisKey = REDIS_STATEMACHINE_KEY_PREFIX + sessionId;
            long deletedCount = redissonClient.getKeys().delete(redisKey);
            if (deletedCount == 0) {
                log.error("[MFA SM Service] [{}] StateMachine not found in Redis, skipping release.", sessionId);
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] Interrupt occurred during SM release.", sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during SM release.", sessionId, e);
        } finally {
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
    }

    private Message<MfaEvent> createEventMessage(MfaEvent event, FactorContext context,
                                                 HttpServletRequest request, Map<String, Object> additionalHeaders) {
        Map<String, Object> headers = new HashMap<>();
        if (context != null) {
            headers.put("sessionId", context.getMfaSessionId());
            if (context.getPrimaryAuthentication() != null && context.getPrimaryAuthentication().getName() != null) {
                headers.put("username", context.getPrimaryAuthentication().getName());
            }
            headers.put("version", context.getVersion());
            headers.put("stateHash", context.calculateStateHash());
            if (context.getPrimaryAuthentication() != null) {
                headers.put("authentication", context.getPrimaryAuthentication());
            }
        }

        if (request != null) {
            Object selectedFactor = request.getAttribute("selectedFactor");
            if (selectedFactor != null) {
                headers.put("selectedFactor", selectedFactor.toString());
            }
        }

        if (additionalHeaders != null && !additionalHeaders.isEmpty()) {
            headers.putAll(additionalHeaders);
        }

        return MessageBuilder.withPayload(event).copyHeaders(headers).build();
    }

    private boolean isTerminalState(MfaState state) {
        if (state == null) return false;
        return state.isTerminal();
    }

    private Object deepCopyIfNeeded(String key, Object value) {
        if (value == null) {
            return null;
        }

        if (isImmutableType(value)) {
            return value;
        }

        try {

            if (value instanceof Set<?> original) {
                java.util.Set<Object> deepCopy = new java.util.LinkedHashSet<>();
                for (Object item : original) {
                    deepCopy.add(deepCopyItem(item));
                }
                return deepCopy;
            }

            if (value instanceof List<?> original) {
                java.util.List<Object> deepCopy = new java.util.ArrayList<>();
                for (Object item : original) {
                    deepCopy.add(deepCopyItem(item));
                }
                return deepCopy;
            }

            if (value instanceof Map<?, ?> original) {
                Map<Object, Object> deepCopy = new java.util.HashMap<>();
                for (java.util.Map.Entry<?, ?> entry : original.entrySet()) {
                    deepCopy.put(
                            deepCopyItem(entry.getKey()),
                            deepCopyItem(entry.getValue())
                    );
                }
                return deepCopy;
            }

            if (value instanceof java.io.Serializable) {
                return org.apache.commons.lang3.SerializationUtils.clone((java.io.Serializable) value);
            }

            log.error("[MFA SM Service] deepCopyIfNeeded - Non-copyable type ({}): {}. Returning original reference.",
                    value.getClass().getName(), key);
            return value;

        } catch (Exception e) {
            log.error("[MFA SM Service] deepCopyIfNeeded - Deep copy failed (key: {}). Returning original reference.", key, e);
            return value;
        }
    }

    private Object deepCopyItem(Object item) {
        if (item == null || isImmutableType(item)) {
            return item;
        }

        if (item instanceof java.io.Serializable) {
            try {
                return org.apache.commons.lang3.SerializationUtils.clone((java.io.Serializable) item);
            } catch (Exception e) {
                log.error("[MFA SM Service] deepCopyItem - Serialization failed. Returning original reference: {}", item.getClass().getName(), e);
                return item;
            }
        }

        log.error("[MFA SM Service] deepCopyItem - Not Serializable. Returning original reference: {}", item.getClass().getName());
        return item;
    }

    private boolean isImmutableType(Object value) {
        return value instanceof String
                || value instanceof Integer
                || value instanceof Long
                || value instanceof Double
                || value instanceof Float
                || value instanceof Boolean
                || value instanceof Character
                || value instanceof Byte
                || value instanceof Short
                || value instanceof java.math.BigDecimal
                || value instanceof java.math.BigInteger
                || value instanceof java.time.LocalDate
                || value instanceof java.time.LocalDateTime
                || value instanceof java.time.ZonedDateTime
                || value instanceof java.time.Instant
                || value instanceof java.util.UUID
                || value.getClass().isEnum();
    }

    private record Result(boolean eventAccepted, MfaState smCurrentStateAfterEvent,
                          FactorContext contextFromSmAfterEvent) {
    }

    public static class MfaStateMachineException extends RuntimeException {
        public MfaStateMachineException(String message) {
            super(message);
        }
        public MfaStateMachineException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}