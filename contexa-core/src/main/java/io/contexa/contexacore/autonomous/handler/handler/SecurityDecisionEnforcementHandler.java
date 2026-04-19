package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.concurrent.CompletableFuture;

@Slf4j
public class SecurityDecisionEnforcementHandler implements SecurityEventHandler {
    private final ZeroTrustActionRepository actionRedisRepository;
    private final SecurityLearningService securityLearningService;
    private final IBlockedUserRecorder blockedUserRecorder;
    private final BlockingSignalBroadcaster blockingDecisionRegistry;
    private final AnalysisTriggerStateRepository analysisTriggerStateRepository;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
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
        this.actionRedisRepository = actionRedisRepository;
        this.securityLearningService = securityLearningService;
        this.blockedUserRecorder = blockedUserRecorder;
        this.blockingDecisionRegistry = blockingDecisionRegistry;
        this.analysisTriggerStateRepository = analysisTriggerStateRepository;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
    }

    private boolean isEnforcementDisabled() {
        return securityZeroTrustProperties != null && !securityZeroTrustProperties.isEnforcementEnabled();
    }

    @Override
    public boolean handle(SecurityEventContext context) {
        Object resultObj = context.getMetadata().get("processingResult");
        if (!(resultObj instanceof ProcessingResult result) || !result.isSuccess()) {
            releasePreTriggerInFlight(context.getSecurityEvent());
            return true;
        }

        SecurityEvent event = context.getSecurityEvent();
        String userId = event.getUserId();
        if (userId == null || userId.isBlank()) {
            return true;
        }

        try {
            enforceDecision(userId, event, result);
            releasePreTriggerInFlight(event);
        } catch (Exception e) {
            releasePreTriggerInFlight(event);
            log.error("[SecurityDecisionEnforcementHandler] Error enforcing decision: eventId={}", event.getEventId(), e);
            context.markAsFailed("Security decision enforcement failed: " + e.getMessage());
            return false;
        }

        if (ZeroTrustAction.fromString(result.getAction()) == ZeroTrustAction.ALLOW) {
            CompletableFuture.runAsync(() -> learnFromResult(userId, event, result))
                    .exceptionally(ex -> {
                        log.error("[SecurityDecisionEnforcementHandler] Baseline learning failed (non-critical): userId={}", userId, ex);
                        return null;
                    });
        }

        return true;
    }

    private void enforceDecision(String userId, SecurityEvent event, ProcessingResult result) {
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
        if (result.getCalibrationApplied() != null) {
            additionalFields.put("calibrationApplied", result.getCalibrationApplied());
        }
        putIfPresent(additionalFields, "calibrationProfileKey", result.getCalibrationProfileKey());
        putIfPresent(additionalFields, "calibrationScenarioClass", result.getCalibrationScenarioClass());
        putIfPresent(additionalFields, "calibrationConfidenceAdjustment", result.getCalibrationConfidenceAdjustment());
        putIfPresent(additionalFields, "calibrationActionBias", result.getCalibrationActionBias());
        putIfPresent(additionalFields, "calibrationSummary", result.getCalibrationSummary());
        if (result.getCalibrationReasons() != null && !result.getCalibrationReasons().isEmpty()) {
            additionalFields.put("calibrationReasons", result.getCalibrationReasons());
        }

        String contextBindingHash = resolveContextBindingHash(event);
        if (contextBindingHash != null) {
            additionalFields.put("contextBindingHash", contextBindingHash);
        }

        if (isEnforcementDisabled()) {
            additionalFields.put("shadowMode", true);
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
                .calibrationApplied(result.getCalibrationApplied())
                .calibrationProfileKey(result.getCalibrationProfileKey())
                .calibrationScenarioClass(result.getCalibrationScenarioClass())
                .calibrationConfidenceAdjustment(result.getCalibrationConfidenceAdjustment())
                .calibrationActionBias(result.getCalibrationActionBias())
                .calibrationReasons(result.getCalibrationReasons())
                .calibrationSummary(result.getCalibrationSummary())
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
    private void releasePreTriggerInFlight(SecurityEvent event) {
        if (analysisTriggerStateRepository == null || event == null || event.getMetadata() == null) {
            return;
        }
        Object triggerSource = event.getMetadata().get("triggerSource");
        Object triggerStateKey = event.getMetadata().get("triggerStateKey");
        if ("PENDING_REDLINE".equals(triggerSource) && triggerStateKey != null && !triggerStateKey.toString().isBlank()) {
            analysisTriggerStateRepository.releaseInFlight(triggerStateKey.toString());
        }
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
