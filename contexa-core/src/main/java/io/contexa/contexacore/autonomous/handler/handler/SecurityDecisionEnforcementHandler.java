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
package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.audit.AgentDecisionRecord;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.DeletedAccountWriteFence;
import io.contexa.contexacore.autonomous.service.LearningPromotionService;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.util.ErrorLogThrottle;
import io.contexa.contexacore.autonomous.agent.AgentContainmentService;
import io.contexa.contexacore.autonomous.agent.AgentScopeService;
import io.contexa.contexacore.autonomous.signal.RiskSignal;
import io.contexa.contexacore.autonomous.signal.RiskSignalEmitter;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

@Slf4j
public class SecurityDecisionEnforcementHandler implements SecurityEventHandler {
    /**
     * Event metadata key holding a successful decision whose observation could not be
     * persisted. A retry of the same event reuses it instead of running the analysis again.
     */
    public static final String AUDIT_PENDING_PROCESSING_RESULT = "auditPendingProcessingResult";
    private static final String DECISION_AUDIT_PENDING = "decisionAuditPending";
    private static final String DECISION_AUDIT_PENDING_AT = "decisionAuditPendingAt";
    private static final Duration DEFAULT_AUDIT_FAILURE_COOLDOWN = Duration.ofSeconds(30);
    private static final Duration OBSERVATION_FAILURE_LOG_INTERVAL = Duration.ofMinutes(1);

    private final ErrorLogThrottle observationFailureLogThrottle = new ErrorLogThrottle(OBSERVATION_FAILURE_LOG_INTERVAL);
    private AgentContainmentService agentContainment;
    private AgentScopeService agentScopes;
    private List<RiskSignalEmitter> riskSignalEmitters = List.of();
    private final ZeroTrustActionRepository actionRedisRepository;
    private final SecurityLearningService securityLearningService;
    private final IBlockedUserRecorder blockedUserRecorder;
    private final BlockingSignalBroadcaster blockingDecisionRegistry;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private final Executor baselineLearningExecutor;
    private final Supplier<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterSupplier;
    private final SecurityContextDataStore securityContextDataStore;
    private final ContextObservationRecorder contextObservationRecorder;
    private VerificationLearningService verificationLearningService;
    private LearningPromotionService learningPromotionService;
    private DeletedAccountWriteFence deletedAccountWriteFence;

    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry) {
        this(actionRedisRepository, securityLearningService, blockedUserRecorder, blockingDecisionRegistry,
                null, Runnable::run, () -> null);
    }

    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        this(actionRedisRepository, securityLearningService, blockedUserRecorder, blockingDecisionRegistry,
                securityZeroTrustProperties, Runnable::run, () -> null);
    }

    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            Executor baselineLearningExecutor) {
        this(actionRedisRepository, securityLearningService, blockedUserRecorder, blockingDecisionRegistry,
                securityZeroTrustProperties, baselineLearningExecutor, () -> null, null);
    }

    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            Executor baselineLearningExecutor,
            Supplier<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterSupplier) {
        this(actionRedisRepository, securityLearningService, blockedUserRecorder, blockingDecisionRegistry,
                securityZeroTrustProperties, baselineLearningExecutor,
                aiSecurityDecisionObservationWriterSupplier, null);
    }

    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            Executor baselineLearningExecutor,
            Supplier<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterSupplier,
            SecurityContextDataStore securityContextDataStore) {
        this(actionRedisRepository, securityLearningService, blockedUserRecorder, blockingDecisionRegistry,
                securityZeroTrustProperties, baselineLearningExecutor, aiSecurityDecisionObservationWriterSupplier,
                securityContextDataStore, null);
    }

    /**
     * @param contextObservationRecorder where the context collectors staged the request's observations; the handler
     *                                   commits them under the final outcome (W2-7), null when nothing is staged
     */
    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            Executor baselineLearningExecutor,
            Supplier<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterSupplier,
            SecurityContextDataStore securityContextDataStore,
            ContextObservationRecorder contextObservationRecorder) {
        this.actionRedisRepository = actionRedisRepository;
        this.securityLearningService = securityLearningService;
        this.blockedUserRecorder = blockedUserRecorder;
        this.blockingDecisionRegistry = blockingDecisionRegistry;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
        this.baselineLearningExecutor = baselineLearningExecutor != null ? baselineLearningExecutor : Runnable::run;
        this.aiSecurityDecisionObservationWriterSupplier = aiSecurityDecisionObservationWriterSupplier != null
                ? aiSecurityDecisionObservationWriterSupplier
                : () -> null;
        this.securityContextDataStore = securityContextDataStore;
        this.contextObservationRecorder = contextObservationRecorder;
    }

    /** Holds the request a restriction stops so that it is learned once the user is verified (W5-2). */
    public void setVerificationLearningService(VerificationLearningService verificationLearningService) {
        this.verificationLearningService = verificationLearningService;
    }

    /** Holds an allowed request whose first-seen values wait for promotion instead of learning it (W5-1). */
    public void setLearningPromotionService(LearningPromotionService learningPromotionService) {
        this.learningPromotionService = learningPromotionService;
    }

    /** Leaves unenforced the result of a request whose account was deleted after it was taken in (Q-15). */
    public void setDeletedAccountWriteFence(DeletedAccountWriteFence deletedAccountWriteFence) {
        this.deletedAccountWriteFence = deletedAccountWriteFence;
    }

    private boolean isEnforcementDisabled() {
        return securityZeroTrustProperties != null && !securityZeroTrustProperties.isEnforcementEnabled();
    }

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        if (!isCurrentProcessingOwner(event)) {
            markStaleResultDiscarded(event);
            return true;
        }
        Object resultObj = context.getMetadata().get("processingResult");
        if (!(resultObj instanceof ProcessingResult result) || !result.isSuccess()) {
            ProcessingResult failedResult = resultObj instanceof ProcessingResult value ? value : null;
            recordAiSecurityDecisionObservation(context.getSecurityEvent(), failedResult, ZeroTrustAction.PENDING_ANALYSIS);
            // No decision was reached: the session's narrative keeps the request, nothing is learned from it.
            commitContextObservations(event, null, false);
            return true;
        }
        String userId = event.getUserId();
        if (userId == null || userId.isBlank()) {
            recordAiSecurityDecisionObservation(event, result, ZeroTrustAction.fromString(result.getAction()));
            commitContextObservations(event, result.getAction(), false);
            return true;
        }

        boolean sideEffectsEnabled = !isEnforcementSuppressed(event);
        // Asked before the observations are committed: a held request is marked so that the work profile leaves it
        // out (W5-1).
        boolean heldForPromotion = sideEffectsEnabled
                && ZeroTrustAction.fromString(result.getAction()) == ZeroTrustAction.ALLOW && holdsForPromotion(event);

        Enforcement enforcement;
        try {
            enforcement = enforceDecision(decisionKey(event, userId), event, result, sideEffectsEnabled);
            // docs/agent A5-5: what the enforcement did, for the decision record written after it.
            event.addMetadata(AgentDecisionRecord.ENFORCEMENT_OUTCOME, switch (enforcement) {
                case APPLIED -> AgentDecisionRecord.APPLIED;
                case KEPT_STRICTER -> AgentDecisionRecord.KEPT_STRICTER;
                case SHADOW -> AgentDecisionRecord.OBSERVED_ONLY;
                case NOT_OWNER -> AgentDecisionRecord.DISCARDED;
            });
            // docs/agent A5-4: a decision on an agent's request may narrow its later requests; the step reaches the
            // decision record with the agent's other steps.
            if (sideEffectsEnabled && (enforcement == Enforcement.APPLIED || enforcement == Enforcement.KEPT_STRICTER)) {
                narrowAgentScope(event, result);
            }
            // docs/agent A5-8: a decision that changed the subject's risk level is sent out to the host's receivers.
            if (sideEffectsEnabled && enforcement == Enforcement.APPLIED) {
                emitRiskSignal(event, decisionKey(event, userId), result);
            }
            if (enforcement != Enforcement.NOT_OWNER && isCurrentProcessingOwner(event)) {
                // Only an applied decision is learnable: a shadow one, and an ALLOW kept out by a stricter action in
                // effect, are committed as decided but not enforced (W5-3).
                commitContextObservations(event, result.getAction(), enforcement == Enforcement.APPLIED);
                if (enforcement != Enforcement.SHADOW) {
                    holdForVerification(event, result.getAction());
                }
            }
        } catch (UnauditedFinalDecisionException e) {
            // Already reported through the throttled observation failure log.
            context.markAsFailed(e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("[SecurityDecisionEnforcementHandler] Error enforcing decision: eventId={}", event.getEventId(), e);
            context.markAsFailed("Security decision enforcement failed: " + e.getMessage());
            return false;
        }

        if (enforcement == Enforcement.APPLIED
                && ZeroTrustAction.fromString(result.getAction()) == ZeroTrustAction.ALLOW) {
            // QF-55: the learning runs on another thread while this request goes on through the next handlers, so it
            // is handed a copy of the event taken here; what either side writes never reaches the other's map.
            SecurityEvent learned = event.detachedCopy();
            Runnable learning = heldForPromotion ? () -> holdForPromotion(learned)
                    : () -> learnFromResult(userId, learned, result);
            CompletableFuture.runAsync(learning, baselineLearningExecutor)
                    .exceptionally(ex -> {
                        log.error("[SecurityDecisionEnforcementHandler] Baseline learning failed (non-critical): userId={}", userId, ex);
                        return null;
                    });
        }

        return true;
    }

    /** What the enforcement of a decision did, so that only an applied decision is learned (W5-3). */
    private enum Enforcement {
        /** The decision is the action in effect. */
        APPLIED,
        /** The processing ownership lapsed and the result was discarded. */
        NOT_OWNER,
        /** The decision was observed in a shadow boundary without runtime effect. */
        SHADOW,
        /** A stricter user-level action stays in effect, so the less strict decision was not written. */
        KEPT_STRICTER
    }

    private Enforcement enforceDecision(String userId, SecurityEvent event, ProcessingResult result,
                                        boolean sideEffectsEnabled) {
        if (!isCurrentProcessingOwner(event)) {
            markStaleResultDiscarded(event);
            return Enforcement.NOT_OWNER;
        }
        String action = result.getAction();
        ZeroTrustAction ztAction;
        if (action == null || action.isBlank()) {
            ztAction = ZeroTrustAction.ESCALATE;
            log.warn("[SecurityDecisionEnforcementHandler] LLM returned no action, defaulting to ESCALATE: userId={}", userId);
        } else {
            ztAction = ZeroTrustAction.fromString(action);
        }

        Map<String, Object> additionalFields = new HashMap<>();
        additionalFields.put("riskScore", result.resolveAuditRiskScore());
        additionalFields.put("confidence", result.resolveAuditConfidence());
        additionalFields.put("reasoning", result.getReasoning());
        additionalFields.put("reasoningSummary", summarizeReasoning(result.getReasoning()));
        additionalFields.put("threatEvidence", result.getThreatIndicators() != null
                ? String.join(", ", result.getThreatIndicators()) : "");
        additionalFields.put("analysisDepth", result.getAiAnalysisLevel());
        putIfPresent(additionalFields, "requestId", resolveRequestId(event));
        if (result.getProposedAction() != null && !result.getProposedAction().isBlank()) {
            additionalFields.put("llmProposedAction", result.getProposedAction());
        }
        putIfPresent(additionalFields, "llmDecisionPresent", result.getLlmDecisionPresent());
        putIfPresent(additionalFields, "technicalFallbackApplied", result.getTechnicalFallbackApplied());
        putIfPresent(additionalFields, "technicalFallbackCategory", result.getTechnicalFallbackCategory());
        putIfPresent(additionalFields, "technicalFallbackReason", result.getTechnicalFallbackReason());
        putIfPresent(additionalFields, "technicalFallbackAction", result.getTechnicalFallbackAction());
        putIfPresent(additionalFields, "responseActionFallbackApplied", result.getResponseActionFallbackApplied());
        putIfPresent(additionalFields, "responseActionFallbackCategory", result.getResponseActionFallbackCategory());
        putIfPresent(additionalFields, "responseActionFallbackReason", result.getResponseActionFallbackReason());
        putIfPresent(additionalFields, "responseActionFallbackAction", result.getResponseActionFallbackAction());
        putIfPresent(additionalFields, "fieldProvenance", result.getFieldProvenance());
        if (Boolean.TRUE.equals(result.getAutonomyConstraintApplied())) {
            additionalFields.put("autonomyConstraintApplied", true);
            additionalFields.put("autonomyConstraintSummary", result.getAutonomyConstraintSummary());
            if (result.getAutonomyConstraintReasons() != null && !result.getAutonomyConstraintReasons().isEmpty()) {
                additionalFields.put("autonomyConstraintReasons", result.getAutonomyConstraintReasons());
            }
            putIfPresent(additionalFields, "autonomyConstraintPolicy", result.getAutonomyConstraintPolicy());
            putIfPresent(additionalFields, "autonomyConstraintSource", result.getAutonomyConstraintSource());
            putIfPresent(additionalFields, "autonomyConstraintVersion", result.getAutonomyConstraintVersion());
        }
        String contextBindingHash = resolveContextBindingHash(event);
        if (contextBindingHash != null) {
            additionalFields.put("contextBindingHash", contextBindingHash);
        }

        event.addMetadata("runtimeEnforcementMode", sideEffectsEnabled ? "ENFORCE" : "SHADOW");
        String observationId = recordAiSecurityDecisionObservation(event, result, ztAction);

        if (!sideEffectsEnabled) {
            additionalFields.put("shadowMode", true);
            additionalFields.put("shadowReason", resolveSuppressionReason(event));
            log.info("[SecurityDecisionEnforcementHandler][SHADOW] Observation-only: decision not persisted and no runtime side-effects applied. userId={}, ztAction={}, proposedAction={}",
                    userId, ztAction, result.getProposedAction());
            return Enforcement.SHADOW;
        }

        // The persisted observation is both the audit record of the decision and the idempotency
        // record that lets a retry restore it without another analysis, so no runtime action is
        // applied without it.
        if (observationId == null || observationId.isBlank()) {
            retainUnauditedDecision(userId, event, result, ztAction, contextBindingHash);
            throw new UnauditedFinalDecisionException();
        }
        additionalFields.put("observationId", observationId);
        putIfPresent(additionalFields, "processingGeneration",
                metadataText(event, SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN));

        if (!isCurrentProcessingOwner(event)) {
            markStaleResultDiscarded(event);
            return Enforcement.NOT_OWNER;
        }
        ZeroTrustActionRepository.FinalActionWrite written =
                actionRedisRepository.writeFinalAction(userId, ztAction, additionalFields);
        if (written == null || written == ZeroTrustActionRepository.FinalActionWrite.FAILED) {
            throw new IllegalStateException("Runtime action did not converge with persisted final observation");
        }
        releaseDecisionAuditPending(userId, contextBindingHash, event);
        if (written == ZeroTrustActionRepository.FinalActionWrite.KEPT_STRICTER) {
            return Enforcement.KEPT_STRICTER;
        }

        if (ztAction == ZeroTrustAction.BLOCK) {
            handleBlockDecision(userId, event, result);
        }
        return Enforcement.APPLIED;
    }

    public void restoreFinalDecision(
            SecurityEvent event, AiSecurityDecisionObservationWriter.PersistedFinalDecision persisted) {
        requireCurrentProcessingOwner(event);
        if (isEnforcementSuppressed(event)
                || "SHADOW".equalsIgnoreCase(persisted.decisionBoundaryMode())
                || "SHADOW".equalsIgnoreCase(persisted.runtimeEnforcementMode())) {
            return;
        }

        // Legacy records without a mode retain the current global/event boundary.
        String userId = event.getUserId();
        if (userId == null || userId.isBlank()) {
            userId = metadataText(event, "userId");
        }
        userId = decisionKey(event, userId);
        ZeroTrustAction action = ZeroTrustAction.fromString(persisted.finalAction());
        Map<String, Object> fields = new HashMap<>();
        fields.put("observationId", persisted.observationId());
        fields.put("processingGeneration", persisted.processingGeneration());
        fields.put("persistedFinalReused", true);
        putIfPresent(fields, "requestId", persisted.requestId());
        putIfPresent(fields, "contextBindingHash", persisted.contextBindingHash());
        putIfPresent(fields, "reasoning", persisted.reasoning());
        requireCurrentProcessingOwner(event);
        ZeroTrustActionRepository.FinalActionWrite written = actionRedisRepository.writeFinalAction(userId, action, fields);
        if (written == null || written == ZeroTrustActionRepository.FinalActionWrite.FAILED) {
            throw new IllegalStateException("Persisted final decision did not converge to runtime action");
        }
        releaseDecisionAuditPending(userId,
                persisted.contextBindingHash() != null ? persisted.contextBindingHash() : resolveContextBindingHash(event),
                event);
        if (action == ZeroTrustAction.BLOCK) {
            ProcessingResult result = ProcessingResult.builder()
                    .success(true).action(action.name()).reasoning(persisted.reasoning()).build();
            handleBlockDecision(userId, event, result);
        }
        commitContextObservations(event, action.name(), written == ZeroTrustActionRepository.FinalActionWrite.APPLIED);
        holdForVerification(event, action.name());
    }

    /** Whether the allowed request waits for promotion before it is learned (W5-1); false without the service. */
    private boolean holdsForPromotion(SecurityEvent event) {
        if (learningPromotionService == null) {
            return false;
        }
        try {
            return learningPromotionService.holds(event);
        } catch (RuntimeException e) {
            log.error("[SecurityDecisionEnforcementHandler] Failed to ask the learning promotion: eventId={}",
                    event.getEventId(), e);
            return false;
        }
    }

    private void holdForPromotion(SecurityEvent event) {
        // Q-15: the hold runs on the learning executor after the enforcement, so the purge may have run in between; a
        // held request is learned with the user's next promotion, which would be a later account's.
        if (discardsAsOfADeletedAccount(event)) {
            return;
        }
        try {
            learningPromotionService.hold(event);
        } catch (RuntimeException e) {
            log.error("[SecurityDecisionEnforcementHandler] Failed to hold a request for promotion: eventId={}",
                    event.getEventId(), e);
        }
    }

    /**
     * Holds the request a restriction stops (CHALLENGE, ESCALATE or BLOCK, as enforced: no action is ESCALATE) so that
     * it is learned once the user is verified (W5-2).
     */
    private void holdForVerification(SecurityEvent event, String action) {
        if (verificationLearningService == null) {
            return;
        }
        ZeroTrustAction enforced = action == null || action.isBlank()
                ? ZeroTrustAction.ESCALATE : ZeroTrustAction.fromString(action);
        if (enforced != ZeroTrustAction.CHALLENGE && enforced != ZeroTrustAction.ESCALATE
                && enforced != ZeroTrustAction.BLOCK) {
            return;
        }
        try {
            verificationLearningService.hold(event, enforced);
        } catch (RuntimeException e) {
            log.error("[SecurityDecisionEnforcementHandler] Failed to hold a stopped request: eventId={}",
                    event.getEventId(), e);
        }
    }

    /** Records the request's staged context observations under its final outcome, once (W2-7). */
    private void commitContextObservations(SecurityEvent event, String outcome, boolean enforced) {
        if (contextObservationRecorder == null) {
            return;
        }
        try {
            contextObservationRecorder.commit(event, outcome != null && !outcome.isBlank() ? outcome : null, enforced);
        } catch (RuntimeException e) {
            log.error("[SecurityDecisionEnforcementHandler] Failed to record context observations: eventId={}",
                    event.getEventId(), e);
        }
    }

    private void requireCurrentProcessingOwner(SecurityEvent event) {
        if (!isCurrentProcessingOwner(event)) {
            markStaleResultDiscarded(event);
            throw new IllegalStateException("Security decision processing ownership is stale or expired");
        }
    }

    /** docs/agent A5-3: what stops an agent whose request a BLOCK decided. */
    public void setAgentContainment(AgentContainmentService agentContainment) {
        this.agentContainment = agentContainment;
    }

    /** docs/agent A5-8: where the risk level changes Contexa's decisions make are sent; none by default. */
    public void setRiskSignalEmitters(List<RiskSignalEmitter> riskSignalEmitters) {
        this.riskSignalEmitters = riskSignalEmitters != null ? List.copyOf(riskSignalEmitters) : List.of();
    }

    private void emitRiskSignal(SecurityEvent event, String decisionKey, ProcessingResult result) {
        if (riskSignalEmitters.isEmpty()) {
            return;
        }
        ZeroTrustAction current = ZeroTrustAction.fromString(result.getAction());
        String currentLevel = RiskSignal.levelOf(current);
        if (currentLevel == null) {
            return;
        }
        String previousLevel;
        try {
            previousLevel = RiskSignal.levelOf(actionRedisRepository.getPreviousActionFromHash(decisionKey));
        } catch (RuntimeException e) {
            log.error("[SecurityDecisionEnforcementHandler] The previous decision could not be read: key={}",
                    decisionKey, e);
            return;
        }
        if (currentLevel.equals(previousLevel)) {
            return;
        }
        ZeroTrustSubject subject = ZeroTrustSubject.of(event);
        RiskSignal signal = new RiskSignal(subject != null ? subject.tenantId() : null, event.getUserId(),
                subject != null ? subject.agentId() : null, previousLevel != null ? previousLevel : RiskSignal.LOW,
                currentLevel, current, result.getReasoning(), Instant.now());
        for (RiskSignalEmitter emitter : riskSignalEmitters) {
            try {
                emitter.emit(signal);
            } catch (RuntimeException e) {
                log.error("[SecurityDecisionEnforcementHandler] A risk signal emitter failed: emitter={}",
                        emitter.getClass().getName(), e);
            }
        }
    }

    /** docs/agent A5-4: what narrows an agent's later requests after a decision on one of them. */
    public void setAgentScopes(AgentScopeService agentScopes) {
        this.agentScopes = agentScopes;
    }

    private void narrowAgentScope(SecurityEvent event, ProcessingResult result) {
        if (agentScopes == null) {
            return;
        }
        try {
            agentScopes.onDecision(event, result).ifPresent(step -> {
                Object earlier = event.getMetadata() != null
                        ? event.getMetadata().get(AgentContainmentService.CONTAINMENT) : null;
                event.addMetadata(AgentContainmentService.CONTAINMENT,
                        earlier != null && !earlier.toString().isBlank() ? earlier + "; " + step : step);
            });
        } catch (RuntimeException e) {
            log.error("[SecurityDecisionEnforcementHandler] Agent scope narrowing failed: eventId={}",
                    event.getEventId(), e);
        }
    }

    /**
     * docs/agent A5-1: the key the request's decision is stored under. An agent acting for a person keeps its decisions
     * apart from the person's; everyone else keeps the user ID.
     */
    private static String decisionKey(SecurityEvent event, String userId) {
        if (userId == null || userId.isBlank()) {
            return userId;
        }
        ZeroTrustSubject subject = ZeroTrustSubject.of(event);
        return subject != null && subject.delegatedAgent() ? subject.storageKey() : userId;
    }

    private void handleBlockDecision(String userId, SecurityEvent event, ProcessingResult result) {
        String requestId = resolveRequestId(event);
        String reasoning = result.getReasoning() != null ? result.getReasoning() : "";

        requireCurrentProcessingOwner(event);
        actionRedisRepository.setBlockedFlag(userId);

        requireCurrentProcessingOwner(event);
        // Signalled before the block is recorded, so responses in flight are cut first; a failed publication is
        // rethrown once the block is recorded, so the record never depends on the signal.
        RuntimeException publicationFailure = null;
        if (blockingDecisionRegistry != null) {
            try {
                blockingDecisionRegistry.registerBlockAndAwait(userId);
            } catch (RuntimeException e) {
                publicationFailure = e;
            }
        }

        try {
            requireCurrentProcessingOwner(event);
        } catch (IllegalStateException e) {
            if (publicationFailure != null) {
                e.addSuppressed(publicationFailure);
            }
            throw e;
        }
        // docs/agent A5-1, A5-3: an agent is no blocked person; its block stays under its own key, and its stop and
        // release are the agent's (the console's agent stops), not the people's block list.
        ZeroTrustSubject subject = ZeroTrustSubject.of(event);
        // docs/agent A5-3: an agent's block stops that agent only: its delegation and tokens, and its accountable
        // person is told. The steps reach the decision record (A5-5).
        if (agentContainment != null && subject != null && subject.agentId() != null) {
            try {
                List<String> steps = agentContainment.onBlock(event, reasoning);
                if (!steps.isEmpty()) {
                    event.addMetadata(AgentContainmentService.CONTAINMENT, String.join("; ", steps));
                }
            } catch (RuntimeException e) {
                log.error("[SecurityDecisionEnforcementHandler] Agent containment failed: userId={}", userId, e);
            }
        }
        if (blockedUserRecorder != null && (subject == null || subject.agentId() == null)) {
            try {
                // A3-3 (R-01): the block keeps the request's tenant for the release's learning.
                Object tenant = event.getMetadata() != null ? event.getMetadata().get("tenantId") : null;
                if (tenant != null && !tenant.toString().isBlank()) {
                    blockedUserRecorder.recordBlock(requestId, userId, event.getUserName(), result.getAction(),
                            reasoning, event.getSourceIp(), event.getUserAgent(), tenant.toString().trim());
                } else {
                    blockedUserRecorder.recordBlock(requestId, userId, event.getUserName(), result.getAction(),
                            reasoning, event.getSourceIp(), event.getUserAgent());
                }
            } catch (Exception ex) {
                log.error("[SecurityDecisionEnforcementHandler] Failed to record block to DB: userId={}", userId, ex);
            }
        }
        if (publicationFailure != null) {
            throw publicationFailure;
        }
    }

    private void learnFromResult(String userId, SecurityEvent event, ProcessingResult result) {
        if (securityLearningService == null) {
            return;
        }
        if (userId == null || userId.isBlank() || result.getAction() == null) {
            return;
        }

        try {
            SecurityDecision decision = buildSecurityDecision(result);
            securityLearningService.learnBaselineOnly(userId, decision, event);
        } catch (Exception e) {
            log.error("[SecurityDecisionEnforcementHandler] Baseline learning failed (non-critical): userId={}", userId, e);
        }
    }

    private SecurityDecision buildSecurityDecision(ProcessingResult result) {
        ZeroTrustAction proposedAction;
        ZeroTrustAction enforcedAction;
        String reasoningPrefix;
        String action = result.getAction();
        String proposed = result.getProposedAction();

        if (proposed != null && !proposed.isBlank()) {
            reasoningPrefix = "AI Native Decision: ";
            proposedAction = ZeroTrustAction.fromString(proposed);
            enforcedAction = action != null && !action.isBlank()
                    ? ZeroTrustAction.fromString(action)
                    : proposedAction;
        } else if (action != null && !action.isBlank()) {
            reasoningPrefix = "AI Native Decision: ";
            proposedAction = ZeroTrustAction.fromString(action);
            enforcedAction = proposedAction;
        } else {
            proposedAction = ZeroTrustAction.ESCALATE;
            enforcedAction = ZeroTrustAction.ESCALATE;
            reasoningPrefix = "AI Analysis Incomplete: ";
        }

        List<String> indicators = result.getThreatIndicators() != null
                ? new ArrayList<>(result.getThreatIndicators()) : new ArrayList<>();
        List<String> mitigationActions = result.getRecommendedActions() != null
                ? new ArrayList<>(result.getRecommendedActions()) : new ArrayList<>();

        return SecurityDecision.builder()
                .action(proposedAction)
                .autonomousAction(enforcedAction)
                .llmDecisionPresent(result.getLlmDecisionPresent())
                .technicalFallbackApplied(result.getTechnicalFallbackApplied())
                .technicalFallbackCategory(result.getTechnicalFallbackCategory())
                .technicalFallbackReason(result.getTechnicalFallbackReason())
                .technicalFallbackAction(result.getTechnicalFallbackAction())
                .responseActionFallbackApplied(result.getResponseActionFallbackApplied())
                .responseActionFallbackCategory(result.getResponseActionFallbackCategory())
                .responseActionFallbackReason(result.getResponseActionFallbackReason())
                .responseActionFallbackAction(result.getResponseActionFallbackAction())
                .confidence(result.getConfidence())
                .llmAuditConfidence(result.resolveAuditConfidence())
                .iocIndicators(indicators)
                .mitigationActions(mitigationActions)
                .reasoning(reasoningPrefix + firstNonBlank(result.getReasoning(), "No additional reasoning"))
                .llmReasoning(result.getLlmReasoning())
                .autonomyConstraintApplied(result.getAutonomyConstraintApplied())
                .autonomyConstraintReasons(result.getAutonomyConstraintReasons())
                .autonomyConstraintSummary(result.getAutonomyConstraintSummary())
                .autonomyConstraintPolicy(result.getAutonomyConstraintPolicy())
                .autonomyConstraintSource(result.getAutonomyConstraintSource())
                .autonomyConstraintVersion(result.getAutonomyConstraintVersion())
                .fieldProvenance(result.getFieldProvenance())
                .build();
    }

    private String summarizeReasoning(String reasoning) {
        if (reasoning == null) {
            return null;
        }
        String normalized = reasoning.replaceAll("\\s+", " ").trim();
        if (normalized.isEmpty()) {
            return null;
        }
        return normalized.length() > 280 ? normalized.substring(0, 280) : normalized;
    }

    private String firstNonBlank(String value, String fallback) {
        return value != null && !value.isBlank() ? value : fallback;
    }

    private String resolveRequestId(SecurityEvent event) {
        if (event != null && event.getMetadata() != null) {
            Object requestId = event.getMetadata().get("requestId");
            if (requestId != null && !requestId.toString().isBlank()) {
                return requestId.toString();
            }
            Object correlationId = event.getMetadata().get("correlationId");
            if (correlationId != null && !correlationId.toString().isBlank()) {
                return correlationId.toString();
            }
        }
        return UUID.randomUUID().toString();
    }

    private String resolveContextBindingHash(SecurityEvent event) {
        if (event != null && event.getMetadata() != null) {
            Object existing = event.getMetadata().get("contextBindingHash");
            if (existing != null && !existing.toString().isBlank()) {
                return existing.toString();
            }
        }
        return SessionFingerprintUtil.generateContextBindingHash(
                event.getSessionId(), event.getSourceIp(), event.getUserAgent());
    }

    private void putIfPresent(Map<String, Object> fields, String key, Object value) {
        if (value != null) {
            fields.put(key, value);
        }
    }

    private boolean isEnforcementSuppressed(SecurityEvent event) {
        return isEnforcementDisabled() || isEventShadowBoundary(event) || discardsAsOfADeletedAccount(event);
    }

    /**
     * Whether the request's account was deleted after the engine took the request in (Q-15): its analysis outlived the
     * purge of the account, so its result is observed as a shadow decision and writes nothing a later account of the
     * same name would inherit (the action in force, the block, the held requests, what is learned). The discarded
     * result is counted.
     */
    private boolean discardsAsOfADeletedAccount(SecurityEvent event) {
        DeletedAccountWriteFence fence = deletedAccountWriteFence;
        return fence != null && event != null
                && fence.discards(DeletedAccountWriteFence.ENFORCEMENT, event.getUserId(), fence.takenInAt(event));
    }

    private boolean isOfADeletedAccount(SecurityEvent event) {
        DeletedAccountWriteFence fence = deletedAccountWriteFence;
        return fence != null && event != null && fence.fenced(event.getUserId(), fence.takenInAt(event));
    }

    private boolean isEventShadowBoundary(SecurityEvent event) {
        String decisionBoundaryMode = metadataText(event, "decisionBoundaryMode");
        return "SHADOW".equalsIgnoreCase(decisionBoundaryMode);
    }

    private String resolveSuppressionReason(SecurityEvent event) {
        if (isEventShadowBoundary(event)) {
            return "EVENT_SHADOW";
        }
        if (isEnforcementDisabled()) {
            return "GLOBAL_SHADOW";
        }
        if (isOfADeletedAccount(event)) {
            return "ACCOUNT_DELETED";
        }
        return "NONE";
    }

    private String recordAiSecurityDecisionObservation(
            SecurityEvent event,
            ProcessingResult result,
            ZeroTrustAction enforcedAction) {
        if (event == null) {
            return null;
        }
        try {
            AiSecurityDecisionObservationWriter writer = aiSecurityDecisionObservationWriterSupplier.get();
            if (writer == null) {
                return null;
            }
            return writer.recordDecision(event, result, enforcedAction);
        } catch (Exception ex) {
            log.error("[SecurityDecisionEnforcementHandler] Failed to record AI security decision observation: eventId={}",
                    event.getEventId(), ex);
            return null;
        }
    }

    private void retainUnauditedDecision(
            String userId,
            SecurityEvent event,
            ProcessingResult result,
            ZeroTrustAction ztAction,
            String contextBindingHash) {
        Duration cooldown = auditFailureCooldown();
        event.addMetadata(AUDIT_PENDING_PROCESSING_RESULT, result);
        event.addMetadata(DECISION_AUDIT_PENDING, true);
        event.addMetadata(DECISION_AUDIT_PENDING_AT, System.currentTimeMillis());
        event.addMetadata(SecurityPlaneAgent.PROCESSING_FAILURE_REPORTED, true);
        try {
            actionRedisRepository.markDecisionAuditPending(userId, contextBindingHash, cooldown);
        } catch (Exception ex) {
            log.error("[SecurityDecisionEnforcementHandler] Failed to mark decision audit pending: userId={}", userId, ex);
        }
        long suppressed = observationFailureLogThrottle.tryAcquire();
        if (suppressed != ErrorLogThrottle.SUPPRESSED) {
            log.error("[SecurityDecisionEnforcementHandler] Final decision was not enforced because its observation "
                            + "could not be persisted ({}). The runtime action stays PENDING_ANALYSIS, the decision is kept "
                            + "for retries of the same event and new analysis for the actor context is suspended for {}ms. "
                            + "userId={}, eventId={}, action={}, similarFailuresSinceLastReport={}",
                    observationFailureCause(), cooldown.toMillis(), userId, event.getEventId(), ztAction, suppressed);
        }
    }

    private void releaseDecisionAuditPending(String userId, String contextBindingHash, SecurityEvent event) {
        if (event != null && event.getMetadata() != null && event.getMetadata().containsKey(AUDIT_PENDING_PROCESSING_RESULT)) {
            event.getMetadata().remove(AUDIT_PENDING_PROCESSING_RESULT);
            event.addMetadata(DECISION_AUDIT_PENDING, false);
        }
        try {
            actionRedisRepository.clearDecisionAuditPending(userId, contextBindingHash);
        } catch (Exception ex) {
            log.error("[SecurityDecisionEnforcementHandler] Failed to clear decision audit pending marker: userId={}", userId, ex);
        }
    }

    private String observationFailureCause() {
        AiSecurityDecisionObservationWriter writer;
        try {
            writer = aiSecurityDecisionObservationWriterSupplier.get();
        } catch (Exception ex) {
            return "decision observation writer is unavailable: " + ex.getMessage();
        }
        if (writer == null) {
            return "no AiSecurityDecisionObservationWriter bean is available";
        }
        if (!writer.isStoreConfigured()) {
            return "the contexaJdbcTemplate decision observation store is not configured";
        }
        return "writing to ctxa_ai_security_decision_observation failed";
    }

    private Duration auditFailureCooldown() {
        if (securityZeroTrustProperties == null || securityZeroTrustProperties.getAnalysis() == null) {
            return DEFAULT_AUDIT_FAILURE_COOLDOWN;
        }
        return Duration.ofMillis(Math.max(0L, securityZeroTrustProperties.getAnalysis().getAuditFailureCooldownMs()));
    }

    private boolean isCurrentProcessingOwner(SecurityEvent event) {
        if (SecurityEventProcessor.hasProcessingDeadlineExceeded(event)) {
            return false;
        }
        String identity = metadataText(event, SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY);
        String ownerToken = metadataText(event, SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN);
        if (identity == null && ownerToken == null) {
            return true;
        }
        return securityContextDataStore != null
                && identity != null
                && ownerToken != null
                && securityContextDataStore.isEventProcessingOwner(identity, ownerToken);
    }

    private void markStaleResultDiscarded(SecurityEvent event) {
        if (event != null) {
            event.addMetadata("staleProcessingResultDiscarded", true);
            event.addMetadata("staleProcessingResultDiscardedAt", System.currentTimeMillis());
        }
    }

    private String metadataText(SecurityEvent event, String key) {
        if (event == null || event.getMetadata() == null || key == null) {
            return null;
        }
        Object value = event.getMetadata().get(key);
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    @Override
    public boolean canHandle(SecurityEventContext context) {
        if (context == null || context.getSecurityEvent() == null) {
            return false;
        }
        return context.getMetadata() != null
                && context.getMetadata().get("processingResult") instanceof ProcessingResult
                || SecurityEventHandler.super.canHandle(context);
    }

    @Override
    public String getName() {
        return "SecurityDecisionEnforcementHandler";
    }

    @Override
    public int getOrder() {
        return 55;
    }

    private static final class UnauditedFinalDecisionException extends IllegalStateException {
        private UnauditedFinalDecisionException() {
            super("Final observation must be persisted before runtime action");
        }
    }
}
