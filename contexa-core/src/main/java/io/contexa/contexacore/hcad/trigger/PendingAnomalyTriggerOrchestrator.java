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
package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacore.hcad.evaluation.HcadEvaluationWriter;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

import java.time.Duration;

@Slf4j
public class PendingAnomalyTriggerOrchestrator {

    private final PendingAnomalyEligibilityGate eligibilityGate;
    private final PendingAnomalyEvidenceCheckService evidenceCheckService;
    private final PendingAnomalyEventTriggerService eventTriggerService;
    private final AnalysisTriggerStateRepository analysisTriggerStateRepository;
    private final HcadProperties hcadProperties;
    private final HcadEvaluationWriter hcadEvaluationWriter;
    private final HcadLlmTriggerCoordinator triggerCoordinator;

    public PendingAnomalyTriggerOrchestrator(
            PendingAnomalyEligibilityGate eligibilityGate,
            PendingAnomalyEvidenceCheckService evidenceCheckService,
            PendingAnomalyEventTriggerService eventTriggerService,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties) {
        this(eligibilityGate, evidenceCheckService, eventTriggerService, analysisTriggerStateRepository, hcadProperties, null);
    }

    public PendingAnomalyTriggerOrchestrator(
            PendingAnomalyEligibilityGate eligibilityGate,
            PendingAnomalyEvidenceCheckService evidenceCheckService,
            PendingAnomalyEventTriggerService eventTriggerService,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties,
            HcadEvaluationWriter hcadEvaluationWriter) {
        this.eligibilityGate = eligibilityGate;
        this.evidenceCheckService = evidenceCheckService;
        this.eventTriggerService = eventTriggerService;
        this.analysisTriggerStateRepository = analysisTriggerStateRepository;
        this.hcadProperties = hcadProperties;
        this.hcadEvaluationWriter = hcadEvaluationWriter;
        this.triggerCoordinator = new HcadLlmTriggerCoordinator(analysisTriggerStateRepository, hcadProperties);
    }

    public void maybeTrigger(HttpServletRequest request, Authentication authentication) {
        HcadPreTriggerMode mode = hcadProperties.getPreTrigger().effectiveMode();
        if (!mode.evaluatesRequest()) {
            return;
        }

        PendingAnomalyEligibility eligibility = eligibilityGate.evaluate(request, authentication);
        if (eligibility == null) {
            return;
        }

        PendingAnomalyEvidenceReport report = evidenceCheckService.evaluate(request, eligibility);
        String evaluationId = recordCandidate(mode, report);
        if (request != null && evaluationId != null) {
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID, evaluationId);
        }
        if (!report.shouldTrigger()) {
            analysisTriggerStateRepository.markNegative(
                    eligibility.baseKey(),
                    Duration.ofSeconds(hcadProperties.getPreTrigger().getNegativeCacheSeconds()));
            return;
        }

        if (protectableAnalysisAlreadyStarted(request)) {
            markDuplicateSuppressed(evaluationId);
            markRequestSuppressed(request, report, report.triggerStateKey(), evaluationId);
            return;
        }

        if (!mode.publishesLlmEvent()) {
            log.debug("[PendingAnomalyTriggerOrchestrator] HCAD pre-trigger observe mode matched but LLM publication is disabled");
            return;
        }
        if (eventTriggerService == null) {
            log.warn("[PendingAnomalyTriggerOrchestrator] HCAD pre-trigger candidate was recorded but no LLM event trigger service is configured");
            return;
        }

        HcadLlmTriggerCoordinator.TriggerLease triggerLease =
                triggerCoordinator.tryAcquire(report, eligibility.baseKey());
        if (!triggerLease.acquired()) {
            if (triggerLease.duplicateSuppressed()) {
                markDuplicateSuppressed(evaluationId);
                markRequestSuppressed(request, report, triggerLease.dedupKey(), evaluationId);
            }
            return;
        }

        boolean success = false;
        try {
            eventTriggerService.publish(request, report, evaluationId);
            triggerCoordinator.markCooldown(triggerLease);
            markTriggered(evaluationId);
            markRequestTriggered(request, report, triggerLease.dedupKey(), evaluationId);
            success = true;
        } catch (Exception ex) {
            log.error("[PendingAnomalyTriggerOrchestrator] Failed to publish pre-protectable threat event", ex);
        } finally {
            if (!success) {
                triggerCoordinator.releaseInFlight(triggerLease);
            }
        }
    }

    private String recordCandidate(HcadPreTriggerMode mode, PendingAnomalyEvidenceReport report) {
        if (hcadEvaluationWriter == null) {
            return null;
        }
        try {
            return hcadEvaluationWriter.recordCandidate(mode, report);
        } catch (Exception ex) {
            log.error("[PendingAnomalyTriggerOrchestrator] Failed to record HCAD evaluation candidate", ex);
            return null;
        }
    }

    private void markTriggered(String evaluationId) {
        if (hcadEvaluationWriter == null) {
            return;
        }
        try {
            hcadEvaluationWriter.markTriggered(evaluationId);
        } catch (Exception ex) {
            log.error("[PendingAnomalyTriggerOrchestrator] Failed to mark HCAD evaluation as triggered", ex);
        }
    }

    private void markDuplicateSuppressed(String evaluationId) {
        if (hcadEvaluationWriter == null) {
            return;
        }
        try {
            hcadEvaluationWriter.markDuplicateSuppressed(evaluationId);
        } catch (Exception ex) {
            log.error("[PendingAnomalyTriggerOrchestrator] Failed to mark duplicate HCAD evaluation", ex);
        }
    }

    private void markRequestTriggered(
            HttpServletRequest request,
            PendingAnomalyEvidenceReport report,
            String dedupKey,
            String evaluationId) {
        if (request == null) {
            return;
        }
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGERED, true);
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_STATE_KEY, dedupKey);
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_DUPLICATE_SUPPRESSED, false);
        if (evaluationId != null && !evaluationId.isBlank()) {
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID, evaluationId);
        }
        if (report != null) {
            if (report.requestId() != null) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_REQUEST_ID, report.requestId());
            }
            if (report.riskSignature() != null) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_RISK_SIGNATURE, report.riskSignature());
            }
        }
    }

    private void markRequestSuppressed(
            HttpServletRequest request,
            PendingAnomalyEvidenceReport report,
            String dedupKey,
            String evaluationId) {
        if (request == null) {
            return;
        }
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGERED, true);
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_STATE_KEY, dedupKey);
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_DUPLICATE_SUPPRESSED, true);
        if (evaluationId != null && !evaluationId.isBlank()) {
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID, evaluationId);
        }
        if (report != null) {
            if (report.requestId() != null) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_REQUEST_ID, report.requestId());
            }
            if (report.riskSignature() != null) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_RISK_SIGNATURE, report.riskSignature());
            }
        }
    }

    private boolean protectableAnalysisAlreadyStarted(HttpServletRequest request) {
        return request != null
                && Boolean.TRUE.equals(request.getAttribute(PendingAnomalyTriggerAttributes.PROTECTABLE_TRIGGER_STARTED));
    }
}
