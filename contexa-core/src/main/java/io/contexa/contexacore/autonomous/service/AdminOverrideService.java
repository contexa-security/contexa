package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
public class AdminOverrideService {

    private final SecurityLearningService securityLearningService;
    private final ZeroTrustActionRedisRepository actionRedisRepository;

    public AdminOverrideService(SecurityLearningService securityLearningService,
                                ZeroTrustActionRedisRepository actionRedisRepository) {
        this.securityLearningService = securityLearningService;
        this.actionRedisRepository = actionRedisRepository;
    }

    public AdminOverride approve(String requestId, String userId, String adminId,
                                 String originalAction, double originalRiskScore, double originalConfidence,
                                 String overriddenAction, String reason,
                                 SecurityEvent originalEvent) {

        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("Reason is required for admin approval");
        }

        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("requestId is required");
        }

        AdminOverride override = AdminOverride.builder()
                .overrideId(UUID.randomUUID().toString())
                .requestId(requestId)
                .userId(userId)
                .adminId(adminId)
                .timestamp(java.time.Instant.now())
                .originalAction(originalAction)
                .overriddenAction(overriddenAction)
                .reason(reason)
                .approved(true)
                .originalRiskScore(originalRiskScore)
                .originalConfidence(originalConfidence)
                .build();

        if (override.canUpdateBaseline()) {
            SecurityEvent eventForLearning = originalEvent != null ? originalEvent :
                    SecurityEvent.builder()
                            .eventId(UUID.randomUUID().toString())
                            .source(SecurityEvent.EventSource.IAM)
                            .userId(userId)
                            .timestamp(LocalDateTime.now())
                            .description("Admin approved override - learning")
                            .build();
            triggerBaselineUpdate(userId, eventForLearning, override);
        }

        if (userId != null && overriddenAction != null) {
            updateAnalysisAction(userId, overriddenAction);
        }
        return override;
    }

    private void triggerBaselineUpdate(String userId, SecurityEvent event, AdminOverride override) {
        try {
            SecurityDecision adminApprovedDecision = SecurityDecision.builder()
                    .action(ZeroTrustAction.ALLOW)
                    .riskScore(override.getOriginalRiskScore())
                    .confidence(0.95)
                    .reasoning("Admin approved: " + override.getReason())
                    .analysisTime(System.currentTimeMillis())
                    .build();

            securityLearningService.learnAndStore(userId, adminApprovedDecision, event);

        } catch (Exception e) {
            log.error("[AdminOverrideService] Baseline update failed: userId={}, overrideId={}",
                    userId, override.getOverrideId(), e);
        }
    }

    private void updateAnalysisAction(String userId, String action) {
        if (userId == null || userId.isBlank()) {
            return;
        }

        try {
            ZeroTrustAction ztAction = ZeroTrustAction.fromString(action);

            if (!ztAction.isBlocking()) {
                actionRedisRepository.approveOverrideAtomically(userId, ztAction);
            } else {
                actionRedisRepository.saveAction(userId, ztAction, null);
            }
        } catch (Exception e) {
            log.error("[AdminOverrideService] Redis analysis update failed: userId={}", userId, e);
        }
    }

}
