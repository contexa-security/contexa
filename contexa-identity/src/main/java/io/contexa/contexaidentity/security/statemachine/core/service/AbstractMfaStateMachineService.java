package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.SerializationUtils;
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

import java.io.Serializable;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Abstract base for MFA StateMachine service implementations.
 * Contains all business logic; subclasses provide lock mechanism only.
 */
@Slf4j
public abstract class AbstractMfaStateMachineService implements MfaStateMachineService {

    protected final StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;
    protected final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;
    protected final StateMachineProperties properties;

    protected static final long LOCK_WAIT_TIME_SECONDS = 10;
    protected static final long LOCK_LEASE_TIME_SECONDS = 30;
    protected static final MfaState FALLBACK_INITIAL_MFA_STATE = MfaState.NONE;

    protected AbstractMfaStateMachineService(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            StateMachineProperties properties) {
        this.stateMachineFactory = stateMachineFactory;
        this.stateMachinePersister = stateMachinePersister;
        this.properties = properties;
    }

    // --- Lock abstraction: subclasses implement ---

    protected abstract boolean tryAcquireLock(String sessionId, long waitTime, TimeUnit unit) throws InterruptedException;

    protected abstract void releaseLock(String sessionId);

    protected abstract void onReleaseStateMachine(String sessionId);

    // --- saveFactorContext hooks (override for Redis-specific validation) ---

    protected void beforeSaveFactorContext(String sessionId) {
        // no-op by default
    }

    protected void afterSaveFactorContext(String sessionId) {
        // no-op by default
    }

    // --- MfaStateMachineService implementation ---

    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            lockAcquired = tryAcquireLock(sessionId, LOCK_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
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
        } catch (MfaStateMachineException e) {
            throw e;
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during SM initialization.", sessionId, e);
            throw new MfaStateMachineException("Error during State Machine initialization for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired) {
                releaseLock(sessionId);
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
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;
        Result eventProcessingResult;

        try {
            lockAcquired = tryAcquireLock(sessionId, LOCK_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[MFA SM Service] [{}] Failed to acquire lock for event ({}) processing.", sessionId, event);
                return false;
            }

            stateMachine = getAndPrepareStateMachine(sessionId, context.getCurrentState(), context);

            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context);

            Message<MfaEvent> message = createEventMessage(event, context, request, additionalHeaders);
            eventProcessingResult = sendEventInternal(stateMachine, message, context);

            if (!eventProcessingResult.eventAccepted()) {
                log.error("[MFA SM Service] [{}] Event ({}) not accepted in current SM state ({}).",
                        sessionId, event, eventProcessingResult.smCurrentStateAfterEvent());
            }

            synchronizeExternalContext(context, eventProcessingResult.contextFromSmAfterEvent(), eventProcessingResult.smCurrentStateAfterEvent());
            StateContextHelper.setFactorContext(stateMachine, context);
            persistStateMachine(stateMachine, sessionId);

            return eventProcessingResult.eventAccepted();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] Interrupt occurred during event ({}) processing.", sessionId, event, e);
            throw new MfaStateMachineException("MFA event processing interrupted: " + sessionId, e);
        } catch (MfaStateMachineException e) {
            throw e;
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during event ({}) processing.", sessionId, event, e);
            throw new MfaStateMachineException("Error during MFA event processing for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired) {
                releaseLock(sessionId);
            }
        }
    }

    @Override
    public FactorContext getFactorContext(String sessionId) {
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;
        try {
            lockAcquired = tryAcquireLock(sessionId, LOCK_WAIT_TIME_SECONDS / 2, TimeUnit.SECONDS);
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
        } catch (MfaStateMachineException e) {
            throw e;
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during FactorContext retrieval.", sessionId, e);
            throw new MfaStateMachineException("Error during getFactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired) {
                releaseLock(sessionId);
            }
        }
    }

    @Override
    public void saveFactorContext(FactorContext context) {
        String sessionId = context.getMfaSessionId();
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            lockAcquired = tryAcquireLock(sessionId, LOCK_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[MFA SM Service] [{}] Failed to acquire lock for FactorContext save.", sessionId);
                throw new MfaStateMachineException("Failed to acquire lock for saving FactorContext: " + sessionId);
            }

            beforeSaveFactorContext(sessionId);

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
            persistStateMachine(stateMachine, sessionId);

            afterSaveFactorContext(sessionId);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] Interrupt occurred during FactorContext save.", sessionId, e);
            throw new MfaStateMachineException("Saving FactorContext interrupted: " + sessionId, e);
        } catch (MfaStateMachineException e) {
            throw e;
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during FactorContext save.", sessionId, e);
            throw new MfaStateMachineException("Error during saving FactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired) {
                releaseLock(sessionId);
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
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            lockAcquired = tryAcquireLock(sessionId, LOCK_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
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
        } catch (MfaStateMachineException e) {
            throw e;
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during state-only update.", sessionId, e);
            throw new MfaStateMachineException("Error during state-only update for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
            if (lockAcquired) {
                releaseLock(sessionId);
            }
        }
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        boolean lockAcquired = false;
        try {
            lockAcquired = tryAcquireLock(sessionId, LOCK_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.error("[MFA SM Service] [{}] Failed to acquire lock for SM release. Timeout.", sessionId);
                return;
            }
            onReleaseStateMachine(sessionId);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] Interrupt occurred during SM release.", sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during SM release.", sessionId, e);
        } finally {
            if (lockAcquired) {
                releaseLock(sessionId);
            }
        }
    }

    // --- Internal methods ---

    protected StateMachine<MfaState, MfaEvent> acquireStateMachine(String sessionId) {
        return stateMachineFactory.getStateMachine(sessionId);
    }

    protected void releaseStateMachineInstance(StateMachine<MfaState, MfaEvent> sm, String sessionId) {
        if (sm != null) {
            try {
                sm.stopReactively().block(Duration.ofSeconds(5));
            } catch (Exception e) {
                log.error("[MFA SM Service] [{}] Error during StateMachine cleanup (ignored): {}", sessionId, e.getMessage());
            }
        }
    }

    protected StateMachine<MfaState, MfaEvent> getAndPrepareStateMachine(String machineId, MfaState initialStateIfNotRestored, FactorContext initialFactorContextForReset) {
        StateMachine<MfaState, MfaEvent> stateMachine = acquireStateMachine(machineId);
        try {
            stateMachinePersister.restore(stateMachine, machineId);

            if (stateMachine.getState() == null || stateMachine.getState().getId() == null) {
                log.error("[MFA SM Service] [{}] State is null after restore. Resetting to initialState: {}", machineId, initialStateIfNotRestored);
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

    protected void updateAndStartStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String machineId, MfaState targetState, FactorContext factorContext) {
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

    protected void resetAndStartStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String machineId, MfaState targetState, FactorContext factorContext) {
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
            log.error("[MFA SM Service] Exception during sendEvent - Event: {}, State: {}, Session: {}",
                    event, currentState, sessionId, e);
            MfaState fallbackState = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
            FactorContext fallbackContext = StateContextHelper.getFactorContext(stateMachine);
            return new Result(false, fallbackState, fallbackContext != null ? fallbackContext : originalExternalContext);
        }

        if (accepted == null) {
            log.error("[MFA SM Service] Event processing timeout - Event: {}, State: {}, Session: {}, Timeout: {}s",
                    event, currentState, sessionId, timeoutSeconds);
            MfaState fallbackState = stateMachine.getState() != null ? stateMachine.getState().getId() : originalExternalContext.getCurrentState();
            FactorContext fallbackContext = StateContextHelper.getFactorContext(stateMachine);
            return new Result(false, fallbackState, fallbackContext != null ? fallbackContext : originalExternalContext);
        }

        boolean eventAccepted = accepted;
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
            log.error("[MFA SM Service] [{}] FactorContext not found inside SM. Only updating external context state to actual SM state.",
                    externalContext.getMfaSessionId());
            externalContext.changeState(smActualState);
        }
    }

    protected void persistStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String sessionId) throws Exception {
        stateMachinePersister.persist(stateMachine, sessionId);
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
            switch (value) {
                case Set<?> original -> {
                    Set<Object> deepCopy = new LinkedHashSet<>();
                    for (Object item : original) {
                        deepCopy.add(deepCopyItem(item));
                    }
                    return deepCopy;
                }
                case List<?> original -> {
                    List<Object> deepCopy = new ArrayList<>();
                    for (Object item : original) {
                        deepCopy.add(deepCopyItem(item));
                    }
                    return deepCopy;
                }
                case Map<?, ?> original -> {
                    Map<Object, Object> deepCopy = new HashMap<>();
                    for (Map.Entry<?, ?> entry : original.entrySet()) {
                        deepCopy.put(deepCopyItem(entry.getKey()), deepCopyItem(entry.getValue()));
                    }
                    return deepCopy;
                }
                case java.io.Serializable serializable -> {
                    return SerializationUtils.clone(serializable);
                }
                default -> {
                }
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
        if (item instanceof Serializable) {
            try {
                return SerializationUtils.clone((Serializable) item);
            } catch (Exception e) {
                log.error("[MFA SM Service] deepCopyItem - Serialization failed. Returning original reference: {}",
                        item.getClass().getName(), e);
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

    protected record Result(boolean eventAccepted, MfaState smCurrentStateAfterEvent,
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
