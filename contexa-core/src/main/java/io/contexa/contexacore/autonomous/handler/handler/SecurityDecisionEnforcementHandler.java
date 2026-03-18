package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Slf4j
@RequiredArgsConstructor
public class SecurityDecisionEnforcementHandler implements SecurityEventHandler {

    private final ZeroTrustActionRepository actionRedisRepository;
    private final SecurityLearningService securityLearningService;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;

    @Setter
    @Autowired(required = false)
    private IBlockedUserRecorder blockedUserRecorder;

    @Setter
    @Autowired(required = false)
    private BlockingSignalBroadcaster blockingDecisionRegistry;

    @Setter
    @Autowired(required = false)
    private ZeroTrustSecurityService zeroTrustSecurityService;

    @Override
    public boolean canHandle(SecurityEventContext context) {
        if (!SecurityEventHandler.super.canHandle(context)) {
            return false;
        }
        if (!securityZeroTrustProperties.isEnforcementEnabled()) {
            SecurityZeroTrustProperties.SecurityMode currentMode = securityZeroTrustProperties.getMode();
            log.error("[SecurityDecisionEnforcementHandler] Enforcement skipped in {} mode: userId={}",
                    currentMode, context.getSecurityEvent().getUserId());
            return false;
        }
        return true;
    }

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
        additionalFields.put("analysisDepth", result.getAiAnalysisLevel());

        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(
                event.getSessionId(), event.getSourceIp(), event.getUserAgent());
        if (contextBindingHash != null) {
            additionalFields.put("contextBindingHash", contextBindingHash);
        }

        actionRedisRepository.saveAction(userId, ztAction, additionalFields);

        // Invalidate decision cache so next request picks up the new action immediately
        if (zeroTrustSecurityService != null) {
            zeroTrustSecurityService.invalidateDecisionCache(userId);
        }

        // Register block signal for in-flight response termination (BLOCK, CHALLENGE, ESCALATE)
        // The signal will be cleared immediately after response termination in handlePendingAnalysis()
        if (ztAction == ZeroTrustAction.BLOCK || ztAction == ZeroTrustAction.CHALLENGE || ztAction == ZeroTrustAction.ESCALATE) {
            if (blockingDecisionRegistry != null) {
                blockingDecisionRegistry.registerBlock(userId, ztAction.name());
            }
        }

        if (ztAction == ZeroTrustAction.BLOCK) {
            handleBlockDecision(userId, event, result);
        }
    }

    private void handleBlockDecision(String userId, SecurityEvent event, ProcessingResult result) {
        String requestId = UUID.randomUUID().toString();
        String reasoning = result.getReasoning() != null ? result.getReasoning() : "";

        actionRedisRepository.setBlockedFlag(userId);

        if (blockedUserRecorder != null) {
            boolean recorded = false;
            for (int attempt = 0; attempt < 2 && !recorded; attempt++) {
                try {
                    blockedUserRecorder.recordBlock(
                            requestId, userId, event.getUserName(),
                            result.getRiskScore(),
                            result.getConfidence(),
                            reasoning,
                            event.getSourceIp(),
                            event.getUserAgent()
                    );
                    recorded = true;
                } catch (Exception ex) {
                    log.error("[SecurityDecisionEnforcementHandler] Failed to record block to DB (attempt {}): userId={}",
                            attempt + 1, userId, ex);
                }
            }
            if (!recorded) {
                log.error("[SecurityDecisionEnforcementHandler] All DB record attempts failed, BLOCK exists only in Redis: userId={}, requestId={}", userId, requestId);
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

        return SecurityDecision.builder()
                .action(decisionAction)
                .riskScore(result.getRiskScore())
                .confidence(result.getConfidence())
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
