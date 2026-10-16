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
        if (baselineLearningService != null && userId != null && !userId.isBlank()) {
            try {
                baselineLearningService.learnIfNormal(userId, decision, event);
            } catch (Exception e) {
                log.error("[SecurityLearningService] Baseline learning failed: userId={}", userId, e);
            }
        }

        if (postProcessor == null) {
            return;
        }
        // The decision of these paths is already in effect (a verified user, an approved override), so its document
        // is stored at once.
        postProcessExecutor.execute(() -> {
            postProcessor.updateSessionContext(event, decision);
            postProcessor.storeInVectorDatabase(event, decision);
        });
    }

    /**
     * Baseline learning only (no vector storage or session update).
     * For use by SecurityDecisionEnforcementHandler where Layer1/Layer2
     * already performed postProcessDecision().
     */
    public void learnBaselineOnly(String userId, SecurityDecision decision, SecurityEvent event) {
        if (baselineLearningService != null && userId != null && !userId.isBlank()) {
            try {
                baselineLearningService.learnIfNormal(userId, decision, event);
            } catch (Exception e) {
                log.error("[SecurityLearningService] Baseline learning failed: userId={}", userId, e);
            }
        }
    }

    /**
     * Baseline learning and vector storage of a request learned after it waited for promotion (W5-1). The session
     * context is not updated again: the request was recorded in its session when it was decided. The stored
     * record replaces the held one of the same event.
     */
    public void learnPromoted(String userId, SecurityDecision decision, SecurityEvent event) {
        learnBaselineOnly(userId, decision, event);
        if (postProcessor == null) {
            return;
        }
        postProcessExecutor.execute(() -> postProcessor.storeInVectorDatabase(event, decision));
    }

    /** Ties the decision documents of the analysis layers to the outcome the enforcement applies (W5-3). */
    public void setContextObservationRecorder(ContextObservationRecorder contextObservationRecorder) {
        this.contextObservationRecorder = contextObservationRecorder;
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
        postProcessExecutor.execute(() -> postProcessor.updateSessionContext(event, decision));
        ContextObservationRecorder recorder = contextObservationRecorder;
        ZeroTrustAction decided = decision != null ? decision.resolveAutonomousAction() : null;
        if (recorder == null || decided == null) {
            return;
        }
        recorder.stage(event, DECISION_DOCUMENT, null, commit -> {
            if (commit.enforced() && decided.name().equalsIgnoreCase(String.valueOf(commit.outcome()))) {
                postProcessExecutor.execute(() -> postProcessor.storeInVectorDatabase(event, decision));
            }
        });
    }
}
