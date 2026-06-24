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
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.hcad.evaluation.HcadEvaluationWriter;
import io.contexa.contexacore.hcad.evaluation.HcadOutcomeClassifier;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAttributes;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;

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
    private final ZeroTrustActionRepository actionRedisRepository;
    private final SecurityLearningService securityLearningService;
    private final IBlockedUserRecorder blockedUserRecorder;
    private final BlockingSignalBroadcaster blockingDecisionRegistry;
    private final AnalysisTriggerStateRepository analysisTriggerStateRepository;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private final Executor baselineLearningExecutor;
    private final HcadEvaluationWriter hcadEvaluationWriter;
    private final Supplier<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterSupplier;

    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry) {
        this(actionRedisRepository, securityLearningService, blockedUserRecorder, blockingDecisionRegistry, null, null);
    }
    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            AnalysisTriggerStateRepository analysisTriggerStateRepository) {
        this(actionRedisRepository, securityLearningService, blockedUserRecorder, blockingDecisionRegistry, analysisTriggerStateRepository, null);
    }
    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        this(
                actionRedisRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingDecisionRegistry,
                analysisTriggerStateRepository,
                securityZeroTrustProperties,
                Runnable::run,
                null);
    }

    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            Executor baselineLearningExecutor) {
        this(
                actionRedisRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingDecisionRegistry,
                analysisTriggerStateRepository,
                securityZeroTrustProperties,
                baselineLearningExecutor,
                null);
    }

    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            Executor baselineLearningExecutor,
            HcadEvaluationWriter hcadEvaluationWriter) {
        this(
                actionRedisRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingDecisionRegistry,
                analysisTriggerStateRepository,
                securityZeroTrustProperties,
                baselineLearningExecutor,
                hcadEvaluationWriter,
                (AiSecurityDecisionObservationWriter) null);
    }

    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            Executor baselineLearningExecutor,
            HcadEvaluationWriter hcadEvaluationWriter,
            AiSecurityDecisionObservationWriter aiSecurityDecisionObservationWriter) {
        this(
                actionRedisRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingDecisionRegistry,
                analysisTriggerStateRepository,
                securityZeroTrustProperties,
                baselineLearningExecutor,
                hcadEvaluationWriter,
                fixedWriterSupplier(aiSecurityDecisionObservationWriter));
    }

    public SecurityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            Executor baselineLearningExecutor,
            HcadEvaluationWriter hcadEvaluationWriter,
            Supplier<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterSupplier) {
        this.actionRedisRepository = actionRedisRepository;
        this.securityLearningService = securityLearningService;
        this.blockedUserRecorder = blockedUserRecorder;
        this.blockingDecisionRegistry = blockingDecisionRegistry;
        this.analysisTriggerStateRepository = analysisTriggerStateRepository;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
        this.baselineLearningExecutor = baselineLearningExecutor != null ? baselineLearningExecutor : Runnable::run;
        this.hcadEvaluationWriter = hcadEvaluationWriter;
        this.aiSecurityDecisionObservationWriterSupplier = aiSecurityDecisionObservationWriterSupplier != null
                ? aiSecurityDecisionObservationWriterSupplier
                : () -> null;
    }

    private static Supplier<AiSecurityDecisionObservationWriter> fixedWriterSupplier(
            AiSecurityDecisionObservationWriter aiSecurityDecisionObservationWriter) {
        return () -> aiSecurityDecisionObservationWriter;
    }

    private boolean isEnforcementDisabled() {
        return securityZeroTrustProperties != null && !securityZeroTrustProperties.isEnforcementEnabled();
    }

    @Override
    public boolean handle(SecurityEventContext context) {
        Object resultObj = context.getMetadata().get("processingResult");
        if (!(resultObj instanceof ProcessingResult result) || !result.isSuccess()) {
            ProcessingResult failedResult = resultObj instanceof ProcessingResult value ? value : null;
            recordAiSecurityDecisionObservation(context.getSecurityEvent(), failedResult, ZeroTrustAction.PENDING_ANALYSIS);
            recordHcadUnknownDecision(context.getSecurityEvent(), failedResult);
            releasePreTriggerInFlight(context.getSecurityEvent());
            return true;
        }

        SecurityEvent event = context.getSecurityEvent();
        String userId = event.getUserId();
        if (userId == null || userId.isBlank()) {
            recordAiSecurityDecisionObservation(event, result, ZeroTrustAction.fromString(result.getAction()));
            return true;
        }

        boolean sideEffectsEnabled = !isEnforcementSuppressed(event);

        try {
            enforceDecision(userId, event, result, sideEffectsEnabled);
            releasePreTriggerInFlight(event);
        } catch (Exception e) {
            releasePreTriggerInFlight(event);
            log.error("[SecurityDecisionEnforcementHandler] Error enforcing decision: eventId={}", event.getEventId(), e);
            context.markAsFailed("Security decision enforcement failed: " + e.getMessage());
            return false;
        }

        if (sideEffectsEnabled && ZeroTrustAction.fromString(result.getAction()) == ZeroTrustAction.ALLOW) {
            CompletableFuture.runAsync(() -> learnFromResult(userId, event, result), baselineLearningExecutor)
                    .exceptionally(ex -> {
                        log.error("[SecurityDecisionEnforcementHandler] Baseline learning failed (non-critical): userId={}", userId, ex);
                        return null;
                    });
        }

        return true;
    }

    private void enforceDecision(String userId, SecurityEvent event, ProcessingResult result, boolean sideEffectsEnabled) {
        String action = result.getAction();
        ZeroTrustAction ztAction;
        if (action == null || action.isBlank()) {
            ztAction = ZeroTrustAction.ESCALATE;
            log.error("[SecurityDecisionEnforcementHandler] LLM returned no action, defaulting to ESCALATE: userId={}", userId);
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
        if (Boolean.TRUE.equals(result.getAutonomyConstraintApplied())) {
            additionalFields.put("autonomyConstraintApplied", true);
            additionalFields.put("autonomyConstraintSummary", result.getAutonomyConstraintSummary());
            if (result.getAutonomyConstraintReasons() != null && !result.getAutonomyConstraintReasons().isEmpty()) {
                additionalFields.put("autonomyConstraintReasons", result.getAutonomyConstraintReasons());
            }
        }
        String contextBindingHash = resolveContextBindingHash(event);
        if (contextBindingHash != null) {
            additionalFields.put("contextBindingHash", contextBindingHash);
        }

        recordHcadDecision(event, result, ztAction);
        recordAiSecurityDecisionObservation(event, result, ztAction);

        if (!sideEffectsEnabled) {
            additionalFields.put("shadowMode", true);
            additionalFields.put("shadowReason", resolveSuppressionReason(event));
            log.info("[SecurityDecisionEnforcementHandler][SHADOW] Observation-only: decision not persisted and no runtime side-effects applied. userId={}, ztAction={}, proposedAction={}",
                    userId, ztAction, result.getProposedAction());
            return;
        }

        actionRedisRepository.saveAction(userId, ztAction, additionalFields);

        if (ztAction == ZeroTrustAction.BLOCK) {
            handleBlockDecision(userId, event, result);
        }
    }

    private void handleBlockDecision(String userId, SecurityEvent event, ProcessingResult result) {
        String requestId = resolveRequestId(event);
        String reasoning = result.getReasoning() != null ? result.getReasoning() : "";

        actionRedisRepository.setBlockedFlag(userId);

        if (blockingDecisionRegistry != null) {
            blockingDecisionRegistry.registerBlock(userId);
        }

        if (blockedUserRecorder != null) {
            try {
                blockedUserRecorder.recordBlock(
                        requestId, userId, event.getUserName(),
                        result.getAction(),
                        reasoning,
                        event.getSourceIp(),
                        event.getUserAgent()
                );
            } catch (Exception ex) {
                log.error("[SecurityDecisionEnforcementHandler] Failed to record block to DB: userId={}", userId, ex);
            }
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
                .confidence(result.getConfidence())
                .llmAuditConfidence(result.resolveAuditConfidence())
                .iocIndicators(indicators)
                .mitigationActions(mitigationActions)
                .reasoning(reasoningPrefix + firstNonBlank(result.getReasoning(), "No additional reasoning"))
                .autonomyConstraintApplied(result.getAutonomyConstraintApplied())
                .autonomyConstraintReasons(result.getAutonomyConstraintReasons())
                .autonomyConstraintSummary(result.getAutonomyConstraintSummary())
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
        return isEnforcementDisabled() || isEventShadowBoundary(event);
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
        return "NONE";
    }

    private void recordHcadDecision(SecurityEvent event, ProcessingResult result, ZeroTrustAction enforcedAction) {
        if (hcadEvaluationWriter == null) {
            return;
        }
        String evaluationId = metadataText(event, "hcadEvaluationId");
        Long llmLatencyMs = result.getProcessingTimeMs() > 0 ? result.getProcessingTimeMs() : null;
        String outcomeClass = isUnknownHcadOutcome(event, result)
                ? HcadOutcomeClassifier.UNKNOWN
                : isHcadTriggeredEvent(event)
                ? HcadOutcomeClassifier.classifyHcadTriggered(result, enforcedAction)
                : HcadOutcomeClassifier.classifyHcadObservation(result, enforcedAction);
        if (evaluationId != null) {
            hcadEvaluationWriter.markDecided(
                    evaluationId,
                    event != null ? event.getEventId() : null,
                    result.getAction(),
                    result.getProposedAction(),
                    result.resolveAuditRiskScore(),
                    result.resolveAuditConfidence(),
                    llmLatencyMs,
                    result.getReasoning(),
                    isParserFailure(result),
                    Boolean.TRUE.equals(result.getTechnicalFallbackApplied()),
                    result.getTechnicalFallbackCategory(),
                    result.getTechnicalFallbackReason(),
                    outcomeClass);
            return;
        }
        if (isHcadPreTriggerObservation(event)) {
            hcadEvaluationWriter.recordObservedDecision(
                    event,
                    result.getAction(),
                    result.getProposedAction(),
                    result.resolveAuditRiskScore(),
                    result.resolveAuditConfidence(),
                    llmLatencyMs,
                    result.getReasoning(),
                    isParserFailure(result),
                    Boolean.TRUE.equals(result.getTechnicalFallbackApplied()),
                    result.getTechnicalFallbackCategory(),
                    result.getTechnicalFallbackReason(),
                    outcomeClass);
        }
    }

    private void recordAiSecurityDecisionObservation(
            SecurityEvent event,
            ProcessingResult result,
            ZeroTrustAction enforcedAction) {
        if (event == null) {
            return;
        }
        try {
            AiSecurityDecisionObservationWriter writer = aiSecurityDecisionObservationWriterSupplier.get();
            if (writer == null) {
                return;
            }
            writer.recordDecision(event, result, enforcedAction);
        } catch (Exception ex) {
            log.error("[SecurityDecisionEnforcementHandler] Failed to record AI security decision observation: eventId={}",
                    event.getEventId(), ex);
        }
    }

    private void recordHcadUnknownDecision(SecurityEvent event, ProcessingResult result) {
        if (hcadEvaluationWriter == null || event == null) {
            return;
        }
        Long llmLatencyMs = result != null && result.getProcessingTimeMs() > 0 ? result.getProcessingTimeMs() : null;
        String evaluationId = metadataText(event, "hcadEvaluationId");
        if (evaluationId != null) {
            hcadEvaluationWriter.markDecided(
                    evaluationId,
                    event.getEventId(),
                    result != null ? result.getAction() : null,
                    result != null ? result.getProposedAction() : null,
                    result != null ? result.resolveAuditRiskScore() : null,
                    result != null ? result.resolveAuditConfidence() : null,
                    llmLatencyMs,
                    result != null ? result.getReasoning() : null,
                    isParserFailure(result),
                    result != null && Boolean.TRUE.equals(result.getTechnicalFallbackApplied()),
                    result != null ? result.getTechnicalFallbackCategory() : null,
                    result != null ? result.getTechnicalFallbackReason() : null,
                    HcadOutcomeClassifier.UNKNOWN);
            return;
        }
        if (isHcadPreTriggerObservation(event)) {
            hcadEvaluationWriter.recordObservedDecision(
                    event,
                    result != null ? result.getAction() : null,
                    result != null ? result.getProposedAction() : null,
                    result != null ? result.resolveAuditRiskScore() : null,
                    result != null ? result.resolveAuditConfidence() : null,
                    llmLatencyMs,
                    result != null ? result.getReasoning() : null,
                    isParserFailure(result),
                    result != null && Boolean.TRUE.equals(result.getTechnicalFallbackApplied()),
                    result != null ? result.getTechnicalFallbackCategory() : null,
                    result != null ? result.getTechnicalFallbackReason() : null,
                    HcadOutcomeClassifier.UNKNOWN);
        }
    }

    private boolean isParserFailure(ProcessingResult result) {
        if (result == null) {
            return false;
        }
        return containsParserFailure(result.getTechnicalFallbackCategory())
                || containsParserFailure(result.getTechnicalFallbackReason());
    }

    private boolean isUnknownHcadOutcome(SecurityEvent event, ProcessingResult result) {
        if (result == null || !result.isSuccess()) {
            return true;
        }
        if (isParserFailure(result)) {
            return true;
        }
        String category = firstText(
                metadataText(event, "structuredOutputFailureCategory"),
                metadataText(event, "securityDecisionParseFailureCategory"),
                metadataText(event, "decisionFailureCategory"),
                result.getTechnicalFallbackCategory());
        String reason = firstText(
                result.getErrorMessage(),
                result.getMessage(),
                result.getTechnicalFallbackReason(),
                metadataText(event, "securityDecisionRawExecutionFailureMessage"),
                metadataText(event, "securityDecisionFallbackReason"),
                metadataText(event, "decisionFailureMessage"));
        if (isFailureCategory(category) || isFailureCategory(reason)) {
            return true;
        }
        String llmDecisionPresent = firstText(
                metadataText(event, "llmDecisionPresent"),
                result.getLlmDecisionPresent());
        return "false".equalsIgnoreCase(llmDecisionPresent);
    }

    private boolean isFailureCategory(String value) {
        String normalized = value == null ? null : value.trim().toLowerCase();
        return normalized != null
                && !normalized.isBlank()
                && !"none".equals(normalized)
                && (normalized.contains("json")
                || normalized.contains("parser")
                || normalized.contains("parse")
                || normalized.contains("timeout")
                || normalized.contains("timed out")
                || normalized.contains("model_unavailable")
                || normalized.contains("model unavailable")
                || normalized.contains("missing_action")
                || normalized.contains("empty_response")
                || normalized.contains("llm_execution_failed"));
    }

    private String firstText(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = value.toString().trim();
            if (!text.isBlank()) {
                return text;
            }
        }
        return null;
    }

    private boolean containsParserFailure(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String normalized = value.trim().toLowerCase();
        return normalized.contains("parser") || normalized.contains("parse");
    }

    private boolean isHcadTriggeredEvent(SecurityEvent event) {
        String triggerSource = metadataText(event, "triggerSource");
        return "HCAD_PRE_TRIGGER".equalsIgnoreCase(triggerSource)
                || "PENDING_REDLINE".equalsIgnoreCase(triggerSource);
    }

    private boolean isHcadPreTriggerObservation(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return false;
        }
        Object evaluated = event.getMetadata().get(HcadPreProtectablePromotionAttributes.METADATA_EVALUATED);
        return Boolean.TRUE.equals(evaluated)
                || event.getMetadata().containsKey(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE)
                || event.getMetadata().containsKey(HcadPreProtectablePromotionAttributes.METADATA_SCORE);
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

    private void releasePreTriggerInFlight(SecurityEvent event) {
        if (analysisTriggerStateRepository == null || event == null || event.getMetadata() == null) {
            return;
        }
        String triggerSource = metadataText(event, "triggerSource");
        Object triggerStateKey = event.getMetadata().get("triggerStateKey");
        if (("PENDING_REDLINE".equalsIgnoreCase(triggerSource) || "HCAD_PRE_TRIGGER".equalsIgnoreCase(triggerSource))
                && triggerStateKey != null && !triggerStateKey.toString().isBlank()) {
            analysisTriggerStateRepository.releaseInFlight(triggerStateKey.toString());
        }
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
}
