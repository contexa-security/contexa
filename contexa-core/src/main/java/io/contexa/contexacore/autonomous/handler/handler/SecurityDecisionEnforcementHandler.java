package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.blocking.BlockingDecisionRegistry;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Slf4j
@RequiredArgsConstructor
public class SecurityDecisionEnforcementHandler implements SecurityEventHandler {

    private final ZeroTrustActionRedisRepository actionRedisRepository;
    private final SecurityLearningService securityLearningService;

    @Setter
    @Autowired(required = false)
    private IBlockedUserRecorder blockedUserRecorder;

    @Setter
    @Autowired(required = false)
    private BlockingDecisionRegistry blockingDecisionRegistry;

    @Override
    public boolean handle(SecurityEventContext context) {
        Object resultObj = context.getMetadata().get("processingResult");
        if (!(resultObj instanceof ProcessingResult result) || !result.isSuccess()) {
            return true;
        }

        SecurityEvent event = context.getSecurityEvent();
        String userId = event.getUserId();
        if (userId == null || userId.isBlank()) {
            return true;
        }

        try {
            enforceDecision(userId, event, result);
        } catch (Exception e) {
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
        additionalFields.put("riskScore", result.getRiskScore());
        additionalFields.put("confidence", result.getConfidence());
        additionalFields.put("threatEvidence", result.getThreatIndicators() != null
                ? String.join(", ", result.getThreatIndicators()) : "");
        additionalFields.put("analysisDepth", result.getAiAnalysisLevel());

        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(
                event.getSessionId(), event.getSourceIp(), event.getUserAgent());
        if (contextBindingHash != null) {
            additionalFields.put("contextBindingHash", contextBindingHash);
        }

        actionRedisRepository.saveAction(userId, ztAction, additionalFields);

        if (ztAction == ZeroTrustAction.BLOCK) {
            handleBlockDecision(userId, event, result);
        }
    }

    private void handleBlockDecision(String userId, SecurityEvent event, ProcessingResult result) {
        String requestId = UUID.randomUUID().toString();
        String reasoning = result.getReasoning() != null ? result.getReasoning() : "";

        actionRedisRepository.setBlockedFlag(userId);

        if (blockingDecisionRegistry != null) {
            blockingDecisionRegistry.registerBlock(userId);
        }

        if (blockedUserRecorder != null) {
            try {
                blockedUserRecorder.recordBlock(
                        requestId, userId, event.getUserName(),
                        result.getRiskScore(),
                        result.getConfidence(),
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
        ZeroTrustAction decisionAction;
        String reasoningPrefix;
        String action = result.getAction();

        if (action != null && !action.isBlank()) {
            reasoningPrefix = "AI Native Decision: ";
            decisionAction = ZeroTrustAction.fromString(action);
        } else {
            decisionAction = ZeroTrustAction.ESCALATE;
            reasoningPrefix = "AI Analysis Incomplete: ";
        }

        List<String> indicators = result.getThreatIndicators() != null
                ? new ArrayList<>(result.getThreatIndicators()) : new ArrayList<>();
        List<String> mitigationActions = result.getRecommendedActions() != null
                ? new ArrayList<>(result.getRecommendedActions()) : new ArrayList<>();

        return SecurityDecision.builder()
                .action(decisionAction)
                .riskScore(result.getRiskScore())
                .confidence(result.getConfidence())
                .iocIndicators(indicators)
                .mitigationActions(mitigationActions)
                .reasoning(reasoningPrefix)
                .build();
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
