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
