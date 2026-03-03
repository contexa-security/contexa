package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachineEventResult;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

@Slf4j
public class StandaloneMfaStateMachineServiceImpl implements MfaStateMachineService {

    private final StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;
    private final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;
    private final StateMachineProperties properties;
    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    private static final long LOCK_WAIT_TIME_SECONDS = 10;
    private static final MfaState FALLBACK_INITIAL_MFA_STATE = MfaState.NONE;

    public StandaloneMfaStateMachineServiceImpl(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            StateMachineProperties properties) {
        this.stateMachineFactory = stateMachineFactory;
        this.stateMachinePersister = stateMachinePersister;
        this.properties = properties;
    }

    private ReentrantLock getLock(String sessionId) {
        return locks.computeIfAbsent(sessionId, k -> new ReentrantLock());
    }

    private StateMachine<MfaState, MfaEvent> acquireStateMachine(String sessionId) {
        return stateMachineFactory.getStateMachine(sessionId);
    }

    private void releaseStateMachineInstance(StateMachine<MfaState, MfaEvent> sm, String sessionId) {
        if (sm != null) {
            try {
                sm.stopReactively().block(Duration.ofSeconds(5));
            } catch (Exception e) {
                log.error("[Standalone MFA SM] [{}] Error during StateMachine cleanup (ignored): {}", sessionId, e.getMessage());
            }
        }
    }

    private StateMachine<MfaState, MfaEvent> getAndPrepareStateMachine(String machineId, MfaState initialStateIfNotRestored, FactorContext initialFactorContextForReset) {
        StateMachine<MfaState, MfaEvent> stateMachine = acquireStateMachine(machineId);
        try {
            stateMachinePersister.restore(stateMachine, machineId);

            if (stateMachine.getState() == null || stateMachine.getState().getId() == null) {
                log.error("[Standalone MFA SM] [{}] State is null after restore. Resetting to initialState: {}", machineId, initialStateIfNotRestored);
                updateAndStartStateMachine(stateMachine, machineId, initialStateIfNotRestored, initialFactorContextForReset);
            } else {
                try {
                    stateMachine.startReactively().block();
                } catch (Exception startEx) {
                    log.error("[Standalone MFA SM] [{}] StateMachine start after restore failed (may already be running): {}", machineId, startEx.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("[Standalone MFA SM] [{}] StateMachine restore failed or new session. Setting initial state: {}. Error: {}", machineId, initialStateIfNotRestored, e.getMessage());
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
    }

    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        ReentrantLock lock = getLock(sessionId);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[Standalone MFA SM] [{}] Failed to acquire lock for SM initialization.", sessionId);
                throw new MfaStateMachineServiceImpl.MfaStateMachineException("Failed to acquire lock for State Machine initialization: " + sessionId);
            }

            stateMachine = acquireStateMachine(sessionId);
            resetAndStartStateMachine(stateMachine, sessionId, context.getCurrentState(), context);

            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context);
            persistStateMachine(stateMachine, sessionId);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[Standalone MFA SM] [{}] Interrupt occurred during SM initialization.", sessionId, e);
            throw new MfaStateMachineServiceImpl.MfaStateMachineException("State Machine initialization interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[Standalone MFA SM] [{}] Error occurred during SM initialization.", sessionId, e);
            throw new MfaStateMachineServiceImpl.MfaStateMachineException("Error during State Machine initialization for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired) {
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
        ReentrantLock lock = getLock(sessionId);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;
        Result eventProcessingResult;

        try {
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[Standalone MFA SM] [{}] Failed to acquire lock for event ({}) processing.", sessionId, event);
                return false;
            }

            stateMachine = getAndPrepareStateMachine(sessionId, context.getCurrentState(), context);

            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context);

            Message<MfaEvent> message = createEventMessage(event, context, request, additionalHeaders);
            eventProcessingResult = sendEventInternal(stateMachine, message, context);

            if (!eventProcessingResult.eventAccepted()) {
                log.error("[Standalone MFA SM] [{}] Event ({}) not accepted in current SM state ({}).", sessionId, event, eventProcessingResult.smCurrentStateAfterEvent());
            }

            synchronizeExternalContext(context, eventProcessingResult.contextFromSmAfterEvent(), eventProcessingResult.smCurrentStateAfterEvent());
            StateContextHelper.setFactorContext(stateMachine, context);
            persistStateMachine(stateMachine, sessionId);

            return eventProcessingResult.eventAccepted();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[Standalone MFA SM] [{}] Interrupt occurred during event ({}) processing.", sessionId, event, e);
            throw new MfaStateMachineServiceImpl.MfaStateMachineException("MFA event processing interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[Standalone MFA SM] [{}] Error occurred during event ({}) processing.", sessionId, event, e);
            throw new MfaStateMachineServiceImpl.MfaStateMachineException("Error during MFA event processing for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired) {
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

        Boolean accepted;
        try {
            accepted = stateMachine.sendEvent(Mono.just(message))
                    .map(result -> result.getResultType() == StateMachineEventResult.ResultType.ACCEPTED)
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .blockFirst(Duration.ofSeconds(timeoutSeconds + 1));
        } catch (Exception e) {
            log.error("[Standalone MFA SM] Exception during sendEvent - Event: {}, State: {}, Session: {}", event, currentState, sessionId, e);
            MfaState fallbackState = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
            FactorContext fallbackContext = StateContextHelper.getFactorContext(stateMachine);
            return new Result(false, fallbackState, fallbackContext != null ? fallbackContext : originalExternalContext);
        }

        if (accepted == null) {
            log.error("[Standalone MFA SM] Event processing timeout - Event: {}, State: {}, Session: {}", event, currentState, sessionId);
            MfaState fallbackState = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
            FactorContext fallbackContext = StateContextHelper.getFactorContext(stateMachine);
            return new Result(false, fallbackState, fallbackContext != null ? fallbackContext : originalExternalContext);
        }

        boolean eventAccepted = Boolean.TRUE.equals(accepted);
        MfaState smStateAfterEvent = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
        FactorContext contextFromSmAfterEvent = StateContextHelper.getFactorContext(stateMachine);

        return new Result(eventAccepted, smStateAfterEvent, contextFromSmAfterEvent);
    }

    private void synchronizeExternalContext(FactorContext externalContext, FactorContext contextFromSm, MfaState smActualState) {
        if (externalContext == null) {
            return;
        }

        if (contextFromSm != null) {
            externalContext.changeState(smActualState);
            externalContext.setVersion(contextFromSm.getVersion());

            if (contextFromSm.getAttributes() != null) {
                contextFromSm.getAttributes().forEach((key, value) -> {
                    Object copiedValue = deepCopyIfNeeded(key, value);
                    externalContext.setAttribute(key, copiedValue);
                });
            }

            externalContext.setCurrentProcessingFactor(contextFromSm.getCurrentProcessingFactor());
            externalContext.setCurrentStepId(contextFromSm.getCurrentStepId());
            externalContext.setMfaRequiredAsPerPolicy(contextFromSm.isMfaRequiredAsPerPolicy());
            externalContext.setRetryCount(contextFromSm.getRetryCount());
            externalContext.setLastError(contextFromSm.getLastError());

            if (contextFromSm.getLastActivityTimestamp() != null) {
                externalContext.updateLastActivityTimestamp();
            }
        } else {
            externalContext.changeState(smActualState);
        }
    }

    private void persistStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String sessionId) throws Exception {
        stateMachinePersister.persist(stateMachine, sessionId);
    }

    @Override
    public FactorContext getFactorContext(String sessionId) {
        ReentrantLock lock = getLock(sessionId);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;
        try {
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS / 2, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[Standalone MFA SM] [{}] Failed to acquire lock for FactorContext retrieval.", sessionId);
                return null;
            }
            stateMachine = getAndPrepareStateMachine(sessionId, FALLBACK_INITIAL_MFA_STATE, null);
            return StateContextHelper.getFactorContext(stateMachine);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[Standalone MFA SM] [{}] Interrupt occurred during FactorContext retrieval.", sessionId, e);
            throw new MfaStateMachineServiceImpl.MfaStateMachineException("Get FactorContext interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[Standalone MFA SM] [{}] Error occurred during FactorContext retrieval.", sessionId, e);
            throw new MfaStateMachineServiceImpl.MfaStateMachineException("Error during getFactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired) {
                lock.unlock();
            }
        }
    }

    @Override
    public void saveFactorContext(FactorContext context) {
        String sessionId = context.getMfaSessionId();
        ReentrantLock lock = getLock(sessionId);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[Standalone MFA SM] [{}] Failed to acquire lock for FactorContext save.", sessionId);
                throw new MfaStateMachineServiceImpl.MfaStateMachineException("Failed to acquire lock for saving FactorContext: " + sessionId);
            }

            stateMachine = acquireStateMachine(sessionId);

            boolean restored = false;
            try {
                stateMachinePersister.restore(stateMachine, sessionId);
                if (stateMachine.getState() != null && stateMachine.getState().getId() != null) {
                    restored = true;
                }
            } catch (Exception e) {
                log.error("[Standalone MFA SM] [{}] SM restore failed. Starting fresh. Error: {}", sessionId, e.getMessage());
            }

            if (!restored) {
                stateMachine.startReactively().block();
            }

            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context);
            persistStateMachine(stateMachine, sessionId);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[Standalone MFA SM] [{}] Interrupt occurred during FactorContext save.", sessionId, e);
            throw new MfaStateMachineServiceImpl.MfaStateMachineException("Saving FactorContext interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[Standalone MFA SM] [{}] Error occurred during FactorContext save.", sessionId, e);
            throw new MfaStateMachineServiceImpl.MfaStateMachineException("Error during saving FactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired) {
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
        log.error("[Standalone MFA SM] [{}] Current state retrieval failed: FactorContext not found. Returning NONE.", sessionId);
        return MfaState.NONE;
    }

    @Override
    public boolean updateStateOnly(String sessionId, MfaState newState) {
        ReentrantLock lock = getLock(sessionId);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[Standalone MFA SM] [{}] Failed to acquire lock for state-only update.", sessionId);
                return false;
            }

            stateMachine = getAndPrepareStateMachine(sessionId, newState, null);
            FactorContext factorContext = StateContextHelper.getFactorContext(stateMachine);

            if (factorContext == null) {
                Authentication currentAuth = stateMachine.getExtendedState().get("authentication", Authentication.class);
                factorContext = new FactorContext(sessionId, currentAuth, newState, null);
            }

            factorContext.changeState(newState);
            updateAndStartStateMachine(stateMachine, sessionId, newState, factorContext);
            persistStateMachine(stateMachine, sessionId);

            return true;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[Standalone MFA SM] [{}] Interrupt occurred during state-only update.", sessionId, e);
            throw new MfaStateMachineServiceImpl.MfaStateMachineException("State-only update interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[Standalone MFA SM] [{}] Error occurred during state-only update.", sessionId, e);
            throw new MfaStateMachineServiceImpl.MfaStateMachineException("Error during state-only update for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired) {
                lock.unlock();
            }
        }
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        locks.remove(sessionId);
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
                    deepCopy.put(deepCopyItem(entry.getKey()), deepCopyItem(entry.getValue()));
                }
                return deepCopy;
            }
            if (value instanceof java.io.Serializable) {
                return org.apache.commons.lang3.SerializationUtils.clone((java.io.Serializable) value);
            }
            return value;
        } catch (Exception e) {
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
                return item;
            }
        }
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
}
