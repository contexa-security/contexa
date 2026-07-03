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

import io.contexa.contexacore.autonomous.LlmAnalysisBackpressureMonitor;
import io.contexa.contexacore.hcad.evaluation.HcadEvaluationWriter;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.util.function.Supplier;

@Slf4j
public class PendingAnomalyTriggerOrchestrator {

    private final PendingAnomalyEligibilityGate eligibilityGate;
    private final PendingAnomalyEvidenceCheckService evidenceCheckService;
    private final PendingAnomalyEventTriggerService eventTriggerService;
    private final AnalysisTriggerStateRepository analysisTriggerStateRepository;
    private final HcadProperties hcadProperties;
    private final HcadEvaluationWriter hcadEvaluationWriter;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private final Supplier<LlmAnalysisBackpressureMonitor> backpressureMonitorSupplier;
    private final HcadLlmTriggerCoordinator triggerCoordinator;

    public PendingAnomalyTriggerOrchestrator(
            PendingAnomalyEligibilityGate eligibilityGate,
            PendingAnomalyEvidenceCheckService evidenceCheckService,
            PendingAnomalyEventTriggerService eventTriggerService,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties) {
        this(eligibilityGate,
                evidenceCheckService,
                eventTriggerService,
                analysisTriggerStateRepository,
                hcadProperties,
                null,
                null,
                null);
    }

    public PendingAnomalyTriggerOrchestrator(
            PendingAnomalyEligibilityGate eligibilityGate,
            PendingAnomalyEvidenceCheckService evidenceCheckService,
            PendingAnomalyEventTriggerService eventTriggerService,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties,
            HcadEvaluationWriter hcadEvaluationWriter) {
        this(eligibilityGate,
                evidenceCheckService,
                eventTriggerService,
                analysisTriggerStateRepository,
                hcadProperties,
                hcadEvaluationWriter,
                null,
                null);
    }

    public PendingAnomalyTriggerOrchestrator(
            PendingAnomalyEligibilityGate eligibilityGate,
            PendingAnomalyEvidenceCheckService evidenceCheckService,
            PendingAnomalyEventTriggerService eventTriggerService,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties,
            HcadEvaluationWriter hcadEvaluationWriter,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        this(eligibilityGate,
                evidenceCheckService,
                eventTriggerService,
                analysisTriggerStateRepository,
                hcadProperties,
                hcadEvaluationWriter,
                securityZeroTrustProperties,
                null);
    }

    public PendingAnomalyTriggerOrchestrator(
            PendingAnomalyEligibilityGate eligibilityGate,
            PendingAnomalyEvidenceCheckService evidenceCheckService,
            PendingAnomalyEventTriggerService eventTriggerService,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties,
            HcadEvaluationWriter hcadEvaluationWriter,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            Supplier<LlmAnalysisBackpressureMonitor> backpressureMonitorSupplier) {
        this.eligibilityGate = eligibilityGate;
        this.evidenceCheckService = evidenceCheckService;
        this.eventTriggerService = eventTriggerService;
        this.analysisTriggerStateRepository = analysisTriggerStateRepository;
        this.hcadProperties = hcadProperties;
        this.hcadEvaluationWriter = hcadEvaluationWriter;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
        this.backpressureMonitorSupplier = backpressureMonitorSupplier == null ? () -> null : backpressureMonitorSupplier;
        this.triggerCoordinator = new HcadLlmTriggerCoordinator(analysisTriggerStateRepository, hcadProperties);
    }

    public void maybeTrigger(HttpServletRequest request, Authentication authentication) {
        HcadPreTriggerMode mode = hcadProperties.getPreTrigger().effectiveMode();
        diagnostic(request, "ENTRY", "mode={} evaluates={} principal={}",
                mode,
                mode.evaluatesRequest(),
                authentication == null ? null : authentication.getName());
        if (!mode.evaluatesRequest()) {
            diagnostic(request, "SKIP", "reason=MODE_DOES_NOT_EVALUATE mode={}", mode);
            return;
        }

        PendingAnomalyEligibility eligibility = eligibilityGate.evaluate(request, authentication);
        if (eligibility == null) {
            diagnostic(request, "SKIP", "reason=ELIGIBILITY_NULL");
            return;
        }
        diagnostic(request, "ELIGIBILITY", "userId={} contextBindingHash={} actorSessionKeyHash={} baseKeyHash={}",
                eligibility.userId(),
                eligibility.contextBindingHash(),
                safeHash(eligibility.actorSessionKey()),
                safeHash(eligibility.baseKey()));

        PendingAnomalyEvidenceReport report = evidenceCheckService.evaluate(request, eligibility);
        if (report == null) {
            diagnostic(request, "SKIP", "reason=EVIDENCE_REPORT_NULL");
            return;
        }
        diagnostic(request, "REPORT", "shouldTrigger={} score={} band={} eligible={} anchors={} corroborating={} riskSignature={} triggerStateKeyHash={}",
                report.shouldTrigger(),
                report.escalationScore(),
                report.escalationBand(),
                report.escalationEligible(),
                report.anchorSignals(),
                report.corroboratingSignals(),
                report.riskSignature(),
                safeHash(report.triggerStateKey()));
        boolean shouldPersist = shouldPersistEvaluation(mode, report);
        String evaluationId = shouldPersist ? recordCandidate(mode, report) : null;
        diagnostic(request, "PERSIST", "shouldPersist={} evaluationId={}", shouldPersist, evaluationId);
        if (request != null && evaluationId != null) {
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID, evaluationId);
        }
        if (!report.shouldTrigger()) {
            diagnostic(request, "NO_TRIGGER", "reason=REPORT_SHOULD_TRIGGER_FALSE baseKeyHash={}", safeHash(eligibility.baseKey()));
            analysisTriggerStateRepository.markNegative(
                    eligibility.baseKey(),
                    Duration.ofSeconds(hcadProperties.getPreTrigger().getNegativeCacheSeconds()));
            return;
        }

        if (protectableAnalysisAlreadyStarted(request)) {
            String activeEvaluationId = triggerCoordinator.findActiveEvaluation(report.triggerStateKey());
            diagnostic(request, "SUPPRESS", "reason=PROTECTABLE_ANALYSIS_ALREADY_STARTED evaluationId={} activeEvaluationId={}", evaluationId, activeEvaluationId);
            markDuplicateSuppressed(evaluationId);
            markRequestSuppressed(request, report, report.triggerStateKey(), evaluationId, activeEvaluationId);
            return;
        }

        if (!mode.publishesLlmEvent()) {
            diagnostic(request, "SUPPRESS", "reason=HCAD_MODE_DOES_NOT_PUBLISH mode={} evaluationId={}", mode, evaluationId);
            markTriggerSuppressed(evaluationId, "HCAD_MODE_" + mode.name());
            log.debug("[PendingAnomalyTriggerOrchestrator] HCAD pre-trigger matched but LLM publication is disabled by HCAD mode. mode={}",
                    mode);
            return;
        }
        if (!llmAnalysisAllowed()) {
            String llmMode = securityZeroTrustMode();
            diagnostic(request, "SUPPRESS", "reason=LLM_MODE_DOES_NOT_ALLOW_ANALYSIS llmMode={} evaluationId={}", llmMode, evaluationId);
            markTriggerSuppressed(evaluationId, "LLM_MODE_" + llmMode);
            log.debug("[PendingAnomalyTriggerOrchestrator] HCAD pre-trigger matched but LLM publication is disabled by AI decision mode. mode={}",
                    llmMode);
            return;
        }
        if (eventTriggerService == null) {
            diagnostic(request, "SUPPRESS", "reason=TRIGGER_SERVICE_UNAVAILABLE evaluationId={}", evaluationId);
            markTriggerSuppressed(evaluationId, "TRIGGER_SERVICE_UNAVAILABLE");
            log.warn("[PendingAnomalyTriggerOrchestrator] HCAD pre-trigger candidate was recorded but no LLM event trigger service is configured");
            return;
        }

        if (hcadPreTriggerBackpressured()) {
            String reason = hcadBackpressureReason();
            diagnostic(request, "SUPPRESS", "reason={} evaluationId={}", reason, evaluationId);
            markTriggerSuppressed(evaluationId, reason);
            log.warn("[PendingAnomalyTriggerOrchestrator] HCAD-only pre-trigger deferred because LLM analysis queue is under backpressure. reason={}",
                    reason);
            return;
        }

        HcadLlmTriggerCoordinator.TriggerLease triggerLease =
                triggerCoordinator.tryAcquire(report, eligibility.baseKey());
        if (!triggerLease.acquired()) {
            diagnostic(request, "LEASE_DENIED", "duplicateSuppressed={} denialReason={} evaluationId={} dedupKeyHash={}",
                    triggerLease.duplicateSuppressed(),
                    triggerLease.denialReason(),
                    evaluationId,
                    safeHash(triggerLease.dedupKey()));
            if (triggerLease.duplicateSuppressed()) {
                String activeEvaluationId = triggerCoordinator.findActiveEvaluation(triggerLease);
                markDuplicateSuppressed(evaluationId);
                markRequestSuppressed(request, report, triggerLease.dedupKey(), evaluationId, activeEvaluationId);
            } else {
                markTriggerSuppressed(evaluationId, triggerLease.denialReason());
            }
            return;
        }
        diagnostic(request, "LEASE_ACQUIRED", "evaluationId={} dedupKeyHash={}", evaluationId, safeHash(triggerLease.dedupKey()));

        boolean success = false;
        try {
            eventTriggerService.publish(request, report, evaluationId, securityZeroTrustMode());
            triggerCoordinator.markCooldown(triggerLease);
            triggerCoordinator.rememberEvaluation(triggerLease, evaluationId);
            markTriggered(evaluationId);
            markRequestTriggered(request, report, triggerLease.dedupKey(), evaluationId);
            diagnostic(request, "PUBLISHED", "evaluationId={} llmMode={} dedupKeyHash={}", evaluationId, securityZeroTrustMode(), safeHash(triggerLease.dedupKey()));
            success = true;
        } catch (Exception ex) {
            diagnostic(request, "PUBLISH_FAILED", "evaluationId={} error={}", evaluationId, ex.getClass().getSimpleName());
            markTriggerSuppressed(evaluationId, "TRIGGER_PUBLICATION_FAILED");
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

    private boolean shouldPersistEvaluation(HcadPreTriggerMode mode, PendingAnomalyEvidenceReport report) {
        if (report == null) {
            return false;
        }
        if (mode == HcadPreTriggerMode.OBSERVE || mode == HcadPreTriggerMode.DISABLED) {
            return false;
        }
        return report.shouldTrigger();
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

    private void markTriggerSuppressed(String evaluationId, String reason) {
        if (hcadEvaluationWriter == null) {
            return;
        }
        try {
            hcadEvaluationWriter.markTriggerSuppressed(evaluationId, reason);
        } catch (Exception ex) {
            log.error("[PendingAnomalyTriggerOrchestrator] Failed to mark suppressed HCAD trigger", ex);
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
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_MERGE_EVALUATION_ID, evaluationId);
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
            String evaluationId,
            String mergeEvaluationId) {
        if (request == null) {
            return;
        }
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGERED, true);
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_STATE_KEY, dedupKey);
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_DUPLICATE_SUPPRESSED, true);
        if (evaluationId != null && !evaluationId.isBlank()) {
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID, evaluationId);
        }
        if (mergeEvaluationId != null && !mergeEvaluationId.isBlank()) {
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_MERGE_EVALUATION_ID, mergeEvaluationId);
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

    private boolean hcadPreTriggerBackpressured() {
        try {
            LlmAnalysisBackpressureMonitor monitor = backpressureMonitorSupplier.get();
            return monitor != null && monitor.hcadPreTriggerBackpressured();
        } catch (Exception ex) {
            log.debug("[PendingAnomalyTriggerOrchestrator] Failed to inspect LLM backpressure state", ex);
            return false;
        }
    }

    private String hcadBackpressureReason() {
        try {
            LlmAnalysisBackpressureMonitor monitor = backpressureMonitorSupplier.get();
            if (monitor != null) {
                return monitor.hcadDeferredReason();
            }
        } catch (Exception ex) {
            log.debug("[PendingAnomalyTriggerOrchestrator] Failed to resolve HCAD backpressure reason", ex);
        }
        return "TRIGGER_DEFERRED_BACKPRESSURE";
    }

    private void diagnostic(HttpServletRequest request, String stage, String message, Object... args) {
        if (!diagnosticEnabled(request)) {
            return;
        }
        Object[] logArgs = new Object[(args == null ? 0 : args.length) + 2];
        logArgs[0] = requestId(request);
        logArgs[1] = stage;
        if (args != null && args.length > 0) {
            System.arraycopy(args, 0, logArgs, 2, args.length);
        }
        log.info("[HCAD-ORCH-DIAG] requestId={} stage={} " + message, logArgs);
    }

    private boolean diagnosticEnabled(HttpServletRequest request) {
        String enabled = request == null ? null : request.getHeader("X-Contexa-HCAD-Diagnostic");
        if ("true".equalsIgnoreCase(enabled) || "1".equals(enabled)) {
            return true;
        }
        String requestId = requestId(request);
        return requestId != null && (requestId.startsWith("opq-") || requestId.startsWith("hcad-"));
    }

    private String requestId(HttpServletRequest request) {
        return request == null ? null : firstText(request.getHeader("X-Request-Id"), request.getParameter("requestId"));
    }

    private String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private String safeHash(String value) {
        return value == null ? null : Integer.toHexString(value.hashCode());
    }

    private boolean protectableAnalysisAlreadyStarted(HttpServletRequest request) {
        return request != null
                && (Boolean.TRUE.equals(request.getAttribute(PendingAnomalyTriggerAttributes.PROTECTABLE_TRIGGER_STARTED))
                || Boolean.TRUE.equals(request.getAttribute(PendingAnomalyTriggerAttributes.PROTECTABLE_TRIGGER_SUPPRESSED)));
    }

    private boolean llmAnalysisAllowed() {
        return securityZeroTrustProperties == null || securityZeroTrustProperties.allowsLlmAnalysis();
    }

    private String securityZeroTrustMode() {
        if (securityZeroTrustProperties == null || securityZeroTrustProperties.getMode() == null) {
            return "UNSPECIFIED";
        }
        return securityZeroTrustProperties.getMode().name();
    }
}
