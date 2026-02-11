package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Slf4j
@RequiredArgsConstructor
public class SecurityDecisionEnforcementHandler implements SecurityEventHandler {

    private final RedisTemplate<String, Object> redisTemplate;
    private final StringRedisTemplate stringRedisTemplate;
    private final AdminOverrideService adminOverrideService;
    private final BaselineLearningService baselineLearningService;

    @Setter
    @Autowired(required = false)
    private IBlockedUserRecorder blockedUserRecorder;

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
        }

        if ("ALLOW".equalsIgnoreCase(result.getAction())) {
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
        if (action == null || action.isBlank()) {
            action = "ESCALATE";
            log.error("[SecurityDecisionEnforcementHandler] LLM returned no action, defaulting to ESCALATE: userId={}", userId);
        }

        Duration ttl = switch (action.toUpperCase()) {
            case "BLOCK" -> null;
            case "ESCALATE" -> Duration.ofMinutes(5);
            case "CHALLENGE" -> Duration.ofMinutes(30);
            default -> Duration.ofSeconds(30);
        };

        String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
        Map<String, Object> fields = new HashMap<>();
        fields.put("action", action);
        fields.put("riskScore", result.getRiskScore());
        fields.put("confidence", result.getConfidence());
        fields.put("threatEvidence", result.getThreatIndicators() != null
                ? String.join(", ", result.getThreatIndicators()) : "");
        fields.put("analysisDepth", result.getAiAnalysisLevel());
        fields.put("updatedAt", java.time.Instant.now().toString());

        redisTemplate.opsForHash().putAll(analysisKey, fields);
        if (ttl != null) {
            redisTemplate.expire(analysisKey, ttl);
        }

        if (stringRedisTemplate != null) {
            String lastActionKey = ZeroTrustRedisKeys.hcadLastVerifiedAction(userId);
            stringRedisTemplate.opsForValue().set(lastActionKey, action, Duration.ofHours(24));
        }

        if ("BLOCK".equalsIgnoreCase(action)) {
            handleBlockDecision(userId, event, result);
        }
    }

    private void handleBlockDecision(String userId, SecurityEvent event, ProcessingResult result) {
        String requestId = UUID.randomUUID().toString();
        String reasoning = result.getReasoning() != null ? result.getReasoning() : "";

        String userBlockedKey = ZeroTrustRedisKeys.userBlocked(userId);
        stringRedisTemplate.opsForValue().set(userBlockedKey, "true");

        if (adminOverrideService != null) {
            adminOverrideService.addToPendingReview(
                    requestId, userId,
                    result.getRiskScore(),
                    result.getConfidence(),
                    reasoning
            );
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
        if (baselineLearningService == null) {
            return;
        }
        if (userId == null || userId.isBlank() || result.getAction() == null) {
            return;
        }

        try {
            SecurityDecision decision = buildSecurityDecision(result);
            baselineLearningService.learnIfNormal(userId, decision, event);
        } catch (Exception e) {
            log.error("[SecurityDecisionEnforcementHandler] Baseline learning failed (non-critical): userId={}", userId, e);
        }
    }

    private SecurityDecision buildSecurityDecision(ProcessingResult result) {
        SecurityDecision.Action decisionAction;
        String reasoningPrefix;
        String action = result.getAction();

        if (action != null && !action.isBlank()) {
            reasoningPrefix = "AI Native Decision: ";
            decisionAction = switch (action.toUpperCase()) {
                case "ALLOW", "A" -> SecurityDecision.Action.ALLOW;
                case "BLOCK", "B" -> SecurityDecision.Action.BLOCK;
                case "CHALLENGE", "C" -> SecurityDecision.Action.CHALLENGE;
                default -> SecurityDecision.Action.ESCALATE;
            };
        } else {
            decisionAction = SecurityDecision.Action.ESCALATE;
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
