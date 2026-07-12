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
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import jakarta.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.SerializationUtils;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachineEventResult;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import reactor.core.publisher.Mono;

/**
 * Abstract base for MFA StateMachine service implementations.
 * Contains all business logic; subclasses provide lock mechanism only.
 */
@Slf4j
public abstract class AbstractMfaStateMachineService implements MfaStateMachineService {

    protected final StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;
    protected final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;
    protected final StateMachineProperties properties;

    protected static final long DEFAULT_LOCK_WAIT_TIME_SECONDS = 10;
    protected static final long DEFAULT_LOCK_LEASE_TIME_SECONDS = 30;
    protected static final long DEFAULT_USER_REQUEST_LOCK_WAIT_TIME_MS = 750;
    protected static final MfaState FALLBACK_INITIAL_MFA_STATE = MfaState.NONE;
    private static final String MFA_REQUEST_ID_HEADER = "X-MFA-Request-Id";
    private static final String REQUEST_ID_HEADER = "X-Request-Id";
    private static final String REQUEST_ID_PARAMETER = "requestId";

    protected AbstractMfaStateMachineService(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            StateMachineProperties properties) {
        this.stateMachineFactory = stateMachineFactory;
        this.stateMachinePersister = stateMachinePersister;
        this.properties = properties;
    }

    protected abstract boolean tryAcquireLock(String sessionId, long waitTime, TimeUnit unit) throws InterruptedException;

    protected abstract void releaseLock(String sessionId);

    protected abstract void onReleaseStateMachine(String sessionId);

    protected void beforeSaveFactorContext(String sessionId) {
    }

    protected void afterSaveFactorContext(String sessionId) {
    }

    protected long lockWaitTimeSeconds() {
        StateMachineProperties.DistributedLockProperties lockProperties = properties.getDistributedLock();
        if (lockProperties == null) {
            return DEFAULT_LOCK_WAIT_TIME_SECONDS;
        }

        int configured = lockProperties.getLockWaitTimeSeconds();
        if (configured <= 0) {
            configured = lockProperties.getTimeoutSeconds();
        }
        return Math.max(1, configured);
    }

    protected long lockLeaseTimeSeconds() {
        StateMachineProperties.DistributedLockProperties lockProperties = properties.getDistributedLock();
        if (lockProperties == null || lockProperties.getLockLeaseTimeSeconds() <= 0) {
            return DEFAULT_LOCK_LEASE_TIME_SECONDS;
        }
        return lockProperties.getLockLeaseTimeSeconds();
    }

    protected long userRequestLockWaitTimeMillis() {
        StateMachineProperties.DistributedLockProperties lockProperties = properties.getDistributedLock();
        if (lockProperties == null || lockProperties.getUserRequestLockWaitTimeMs() < 0) {
            return DEFAULT_USER_REQUEST_LOCK_WAIT_TIME_MS;
        }
        return lockProperties.getUserRequestLockWaitTimeMs();
    }

    protected long busyRetryAfterMillis() {
        return Math.max(1_000L, userRequestLockWaitTimeMillis());
    }

    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            lockAcquired = tryAcquireLock(sessionId, userRequestLockWaitTimeMillis(), TimeUnit.MILLISECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] MFA session is busy during SM initialization.", sessionId);
                throw new MfaStateMachineBusyException(sessionId, null, busyRetryAfterMillis());
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
            lockAcquired = tryAcquireLock(sessionId, userRequestLockWaitTimeMillis(), TimeUnit.MILLISECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] MFA session is busy during event ({}) processing.", sessionId, event);
                throw new MfaStateMachineBusyException(sessionId, event, busyRetryAfterMillis());
            }

            stateMachine = getAndPrepareStateMachine(sessionId, context.getCurrentState(), context);
            FactorContext persistedContext = StateContextHelper.getFactorContext(stateMachine);
            String requestId = resolveRequestId(event, context, request, additionalHeaders);

            if (isDuplicateRequest(event, persistedContext, requestId)) {
                MfaState currentState = currentStateOf(stateMachine, context);
                log.info("[MFA SM Service] [{}] Duplicate request ignored for event ({}) requestId={}.",
                        sessionId, event, requestId);
                synchronizeExternalContext(context, persistedContext, currentState);
                return lastEventAccepted(persistedContext);
            }

            verifyOptimisticVersion(context, persistedContext, event);

            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context);

            Map<String, Object> eventHeaders = new HashMap<>();
            if (additionalHeaders != null && !additionalHeaders.isEmpty()) {
                eventHeaders.putAll(additionalHeaders);
            }
            if (hasText(requestId)) {
                eventHeaders.putIfAbsent("requestId", requestId);
            }

            Message<MfaEvent> message = createEventMessage(event, context, request, eventHeaders);
            eventProcessingResult = sendEventInternal(stateMachine, message, context);

            if (!eventProcessingResult.eventAccepted()) {
                log.warn("[MFA SM Service] [{}] Event ({}) not accepted in current SM state ({}).",
                        sessionId, event, eventProcessingResult.smCurrentStateAfterEvent());
            }

            synchronizeExternalContext(context, eventProcessingResult.contextFromSmAfterEvent(), eventProcessingResult.smCurrentStateAfterEvent());
            recordIdempotency(context, requestId, event, eventProcessingResult.eventAccepted(),
                    eventProcessingResult.smCurrentStateAfterEvent());
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
        StateMachine<MfaState, MfaEvent> stateMachine = null;
        try {
            stateMachine = acquireStateMachine(sessionId);
            stateMachinePersister.restore(stateMachine, sessionId);
            return StateContextHelper.getFactorContext(stateMachine);

        } catch (MfaStateMachineException e) {
            throw e;
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] Error occurred during FactorContext retrieval.", sessionId, e);
            throw new MfaStateMachineException("Error during getFactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            releaseStateMachineInstance(stateMachine, sessionId);
        }
    }

    @Override
    public void saveFactorContext(FactorContext context) {
        String sessionId = context.getMfaSessionId();
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            lockAcquired = tryAcquireLock(sessionId, lockWaitTimeSeconds(), TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] Failed to acquire lock for FactorContext save.", sessionId);
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
            lockAcquired = tryAcquireLock(sessionId, lockWaitTimeSeconds(), TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] Failed to acquire lock for state-only update.", sessionId);
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
            lockAcquired = tryAcquireLock(sessionId, lockWaitTimeSeconds(), TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] Failed to acquire lock for SM release. Timeout.", sessionId);
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
                properties.getMfa().getTransitionTimeoutSeconds() : 30;

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

    private void verifyOptimisticVersion(FactorContext externalContext, FactorContext persistedContext,
                                         MfaEvent event) {
        if (externalContext == null || persistedContext == null) {
            return;
        }

        int expectedVersion = externalContext.getVersion();
        int persistedVersion = persistedContext.getVersion();
        if (expectedVersion != persistedVersion) {
            throw new MfaStateMachineOptimisticLockException(
                    externalContext.getMfaSessionId(), event, expectedVersion, persistedVersion);
        }
    }

    private boolean isDuplicateRequest(MfaEvent event, FactorContext persistedContext, String requestId) {
        if (!hasText(requestId) || persistedContext == null) {
            return false;
        }

        Object lastRequestId = persistedContext.getAttribute(FactorContextAttributes.Idempotency.LAST_REQUEST_ID);
        Object lastEvent = persistedContext.getAttribute(FactorContextAttributes.Idempotency.LAST_EVENT);
        return requestId.equals(lastRequestId) && event.name().equals(String.valueOf(lastEvent));
    }

    private boolean lastEventAccepted(FactorContext persistedContext) {
        if (persistedContext == null) {
            return false;
        }
        Object accepted = persistedContext.getAttribute(FactorContextAttributes.Idempotency.LAST_EVENT_ACCEPTED);
        return !(accepted instanceof Boolean) || (Boolean) accepted;
    }

    private void recordIdempotency(FactorContext context, String requestId, MfaEvent event,
                                   boolean accepted, MfaState state) {
        if (context == null || !hasText(requestId)) {
            return;
        }

        context.setAttribute(FactorContextAttributes.Idempotency.LAST_REQUEST_ID, requestId);
        context.setAttribute(FactorContextAttributes.Idempotency.LAST_EVENT, event.name());
        context.setAttribute(FactorContextAttributes.Idempotency.LAST_EVENT_ACCEPTED, accepted);
        context.setAttribute(FactorContextAttributes.Idempotency.LAST_EVENT_STATE,
                state != null ? state.name() : null);
        context.setAttribute(FactorContextAttributes.Idempotency.LAST_EVENT_VERSION, context.getVersion());
    }

    private MfaState currentStateOf(StateMachine<MfaState, MfaEvent> stateMachine, FactorContext fallbackContext) {
        if (stateMachine != null && stateMachine.getState() != null && stateMachine.getState().getId() != null) {
            return stateMachine.getState().getId();
        }
        return fallbackContext != null ? fallbackContext.getCurrentState() : FALLBACK_INITIAL_MFA_STATE;
    }

    private String resolveRequestId(MfaEvent event, FactorContext context, HttpServletRequest request,
                                    Map<String, Object> additionalHeaders) {
        if (additionalHeaders != null) {
            Object headerValue = additionalHeaders.get("requestId");
            if (headerValue == null) {
                headerValue = additionalHeaders.get("request-id");
            }
            if (headerValue != null && hasText(headerValue.toString())) {
                return headerValue.toString();
            }
        }

        if (request != null) {
            String requestId = firstText(request.getHeader(MFA_REQUEST_ID_HEADER), request.getHeader(REQUEST_ID_HEADER),
                    request.getParameter(REQUEST_ID_PARAMETER), request.getParameter("mfaRequestId"));
            if (hasText(requestId)) {
                return requestId;
            }
        }

        return null;
    }

    private String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
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
                Set<Object> deepCopy = new LinkedHashSet<>();
                for (Object item : original) {
                    deepCopy.add(deepCopyItem(item));
                }
                return deepCopy;
            } else if (value instanceof List<?> original) {
                List<Object> deepCopy = new ArrayList<>();
                for (Object item : original) {
                    deepCopy.add(deepCopyItem(item));
                }
                return deepCopy;
            } else if (value instanceof Map<?, ?> original) {
                Map<Object, Object> deepCopy = new HashMap<>();
                for (Map.Entry<?, ?> entry : original.entrySet()) {
                    deepCopy.put(deepCopyItem(entry.getKey()), deepCopyItem(entry.getValue()));
                }
                return deepCopy;
            } else if (value instanceof Serializable serializable) {
                return SerializationUtils.clone(serializable);
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
                || value instanceof BigDecimal
                || value instanceof BigInteger
                || value instanceof LocalDate
                || value instanceof LocalDateTime
                || value instanceof ZonedDateTime
                || value instanceof Instant
                || value instanceof UUID
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

    public static class MfaStateMachineBusyException extends MfaStateMachineException {
        private final String sessionId;
        private final MfaEvent event;
        private final long retryAfterMs;

        public MfaStateMachineBusyException(String sessionId, MfaEvent event, long retryAfterMs) {
            super("MFA session is busy: " + sessionId);
            this.sessionId = sessionId;
            this.event = event;
            this.retryAfterMs = retryAfterMs;
        }

        public String getSessionId() {
            return sessionId;
        }

        public MfaEvent getEvent() {
            return event;
        }

        public long getRetryAfterMs() {
            return retryAfterMs;
        }
    }

    public static class MfaStateMachineOptimisticLockException extends MfaStateMachineException {
        private final String sessionId;
        private final MfaEvent event;
        private final int expectedVersion;
        private final int actualVersion;

        public MfaStateMachineOptimisticLockException(String sessionId, MfaEvent event,
                                                      int expectedVersion, int actualVersion) {
            super("Stale MFA FactorContext for session " + sessionId
                    + " event " + event
                    + " expectedVersion=" + expectedVersion
                    + " actualVersion=" + actualVersion);
            this.sessionId = sessionId;
            this.event = event;
            this.expectedVersion = expectedVersion;
            this.actualVersion = actualVersion;
        }

        public String getSessionId() {
            return sessionId;
        }

        public MfaEvent getEvent() {
            return event;
        }

        public int getExpectedVersion() {
            return expectedVersion;
        }

        public int getActualVersion() {
            return actualVersion;
        }
    }
}
