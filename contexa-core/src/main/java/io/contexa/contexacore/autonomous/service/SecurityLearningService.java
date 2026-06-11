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

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SecurityLearningService {

    private final BaselineLearningService baselineLearningService;
    private final SecurityDecisionPostProcessor postProcessor;

    public SecurityLearningService(BaselineLearningService baselineLearningService,
                                   SecurityDecisionPostProcessor postProcessor) {
        this.baselineLearningService = baselineLearningService;
        this.postProcessor = postProcessor;
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

        postProcessDecision(event, decision);
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
     * Session context update + vector DB storage only.
     * Use for analysis layer results (Layer1, Layer2) where baseline learning is not needed.
     */
    public void postProcessDecision(SecurityEvent event, SecurityDecision decision) {
        if (postProcessor == null) {
            return;
        }
        postProcessor.updateSessionContext(event, decision);
        postProcessor.storeInVectorDatabase(event, decision);
    }
}
