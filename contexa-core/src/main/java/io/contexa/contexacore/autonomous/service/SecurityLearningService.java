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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRun;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.Executor;

@Slf4j
public class SecurityLearningService {

    private final BaselineLearningService baselineLearningService;
    private final SecurityDecisionPostProcessor postProcessor;
    private final Executor postProcessExecutor;

    /** The name the decision document of an analysis layer is staged under until its decision is enforced (W5-3). */
    public static final String DECISION_DOCUMENT = "SECURITY_DECISION_DOCUMENT";

    private volatile ContextObservationRecorder contextObservationRecorder;
    private volatile DeletedAccountWriteFence deletedAccountWriteFence;

    public SecurityLearningService(BaselineLearningService baselineLearningService,
                                   SecurityDecisionPostProcessor postProcessor) {
        this(baselineLearningService, postProcessor, Runnable::run);
    }

    public SecurityLearningService(BaselineLearningService baselineLearningService,
                                   SecurityDecisionPostProcessor postProcessor,
                                   Executor postProcessExecutor) {
        this.baselineLearningService = baselineLearningService;
        this.postProcessor = postProcessor;
        this.postProcessExecutor = postProcessExecutor != null ? postProcessExecutor : Runnable::run;
    }

    /**
     * Baseline learning + session context update + vector DB storage.
     * Use when action transitions to ALLOW via LLM involvement:
     * - LLM CHALLENGE -> MFA success -> ALLOW
     * - LLM analysis -> ALLOW
     * - BLOCK -> admin override -> ALLOW
     */
    public void learnAndStore(String userId, SecurityDecision decision, SecurityEvent event) {
        long takenInAt = takenInAt(event);
        learnBaseline(userId, decision, event, takenInAt);

        if (postProcessor == null) {
            return;
        }
        // The decision of these paths is already in effect (a verified user, an approved override), so its document
        // is stored at once.
        postProcessExecutor.execute(() -> {
            updateSessionContext(event, decision, takenInAt);
            storeDocument(event, decision, takenInAt);
        });
    }

    /**
     * Baseline learning only (no vector storage or session update).
     * For use by SecurityDecisionEnforcementHandler where Layer1/Layer2
     * already performed postProcessDecision().
     */
    public void learnBaselineOnly(String userId, SecurityDecision decision, SecurityEvent event) {
        learnBaseline(userId, decision, event, takenInAt(event));
    }

    /**
     * Baseline learning and vector storage of a request learned after it waited for promotion (W5-1). The session
     * context is not updated again: the request was recorded in its session when it was decided. The stored
     * record replaces the held one of the same event.
     */
    public void learnPromoted(String userId, SecurityDecision decision, SecurityEvent event) {
        learnRecorded(userId, decision, event);
    }

    /**
     * Baseline learning and vector storage of a request sent again after its user passed a step-up (N-LRN-3). The
     * session context is not updated: the request was recorded in its session when the decision in force answered it.
     */
    public void learnVerifiedResend(String userId, SecurityDecision decision, SecurityEvent event) {
        learnRecorded(userId, decision, event);
    }

    /** Baseline learning and vector storage of a request its session already recorded. */
    private void learnRecorded(String userId, SecurityDecision decision, SecurityEvent event) {
        long takenInAt = takenInAt(event);
        learnBaseline(userId, decision, event, takenInAt);
        if (postProcessor == null) {
            return;
        }
        postProcessExecutor.execute(() -> storeDocument(event, decision, takenInAt));
    }

    /** Ties the decision documents of the analysis layers to the outcome the enforcement applies (W5-3). */
    public void setContextObservationRecorder(ContextObservationRecorder contextObservationRecorder) {
        this.contextObservationRecorder = contextObservationRecorder;
    }

    /** Discards the late writes of a request whose account was deleted after it was taken in (Q-15). */
    public void setDeletedAccountWriteFence(DeletedAccountWriteFence deletedAccountWriteFence) {
        this.deletedAccountWriteFence = deletedAccountWriteFence;
    }

    /**
     * The session context update of an analysis layer's result (Layer1, Layer2), and its decision document once the
     * decision is enforced (W5-3): the document is staged with the request's observations and stored when the
     * enforcement commits the same outcome as applied. A shadow decision, a result without processing ownership, an
     * ALLOW kept out by a stricter action in effect, or an earlier layer's result replaced by a later one stores no
     * document. Without the recorder no outcome is known, so no document is stored.
     */
    public void postProcessDecision(SecurityEvent event, SecurityDecision decision) {
        // W6-9: a shadow run's copy leaves the session and the decision documents alone.
        if (postProcessor == null || PromptShadowRun.isShadow(event)) {
            return;
        }
        long takenInAt = takenInAt(event);
        postProcessExecutor.execute(() -> updateSessionContext(event, decision, takenInAt));
        ContextObservationRecorder recorder = contextObservationRecorder;
        ZeroTrustAction decided = decision != null ? decision.resolveAutonomousAction() : null;
        if (recorder == null || decided == null) {
            return;
        }
        recorder.stage(event, DECISION_DOCUMENT, null, commit -> {
            if (commit.enforced() && decided.name().equalsIgnoreCase(String.valueOf(commit.outcome()))) {
                postProcessExecutor.execute(() -> storeDocument(event, decision, takenInAt));
            }
        });
    }

    /** When the engine took the event in, for the deleted account fence; unused without the fence. */
    private long takenInAt(SecurityEvent event) {
        DeletedAccountWriteFence fence = deletedAccountWriteFence;
        return fence != null ? fence.takenInAt(event) : 0L;
    }

    /** Whether the write is a late one of a request whose account was deleted after it was taken in (Q-15). */
    private boolean discards(String write, String userId, long takenInAt) {
        DeletedAccountWriteFence fence = deletedAccountWriteFence;
        return fence != null && fence.discards(write, userId, takenInAt);
    }

    private void learnBaseline(String userId, SecurityDecision decision, SecurityEvent event, long takenInAt) {
        if (baselineLearningService == null || userId == null || userId.isBlank()
                || discards(DeletedAccountWriteFence.BASELINE, userId, takenInAt)) {
            return;
        }
        try {
            baselineLearningService.learnIfNormal(userId, decision, event);
        } catch (Exception e) {
            log.error("[SecurityLearningService] Baseline learning failed: userId={}", userId, e);
        }
    }

    private void updateSessionContext(SecurityEvent event, SecurityDecision decision, long takenInAt) {
        if (!discards(DeletedAccountWriteFence.SESSION_CONTEXT, event.getUserId(), takenInAt)) {
            postProcessor.updateSessionContext(event, decision);
        }
    }

    /**
     * Stores the decision document of the request unless its account was deleted after the request was taken in. A
     * document stored while the purge of that account ran is removed again: the purge may not have seen it (Q-15).
     */
    private void storeDocument(SecurityEvent event, SecurityDecision decision, long takenInAt) {
        String userId = event.getUserId();
        if (discards(DeletedAccountWriteFence.DECISION_DOCUMENT, userId, takenInAt)) {
            return;
        }
        postProcessor.storeInVectorDatabase(event, decision);
        if (discards(DeletedAccountWriteFence.DECISION_DOCUMENT_REMOVED, userId, takenInAt)) {
            postProcessor.removeStoredRecord(event, decision);
        }
    }
}
