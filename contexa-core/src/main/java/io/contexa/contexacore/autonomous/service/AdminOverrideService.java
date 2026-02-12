package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Slf4j
public class AdminOverrideService {

    private final AdminOverrideRepository repository;
    private final BaselineLearningService baselineLearningService;
    private final ZeroTrustActionRedisRepository actionRedisRepository;

    public AdminOverrideService(AdminOverrideRepository repository,
                                BaselineLearningService baselineLearningService,
                                ZeroTrustActionRedisRepository actionRedisRepository) {
        this.repository = repository;
        this.baselineLearningService = baselineLearningService;
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
                .timestamp(Instant.now())
                .originalAction(originalAction)
                .overriddenAction(overriddenAction)
                .reason(reason)
                .approved(true)
                .originalRiskScore(originalRiskScore)
                .originalConfidence(originalConfidence)
                .build();

        repository.save(override);

        repository.deletePending(requestId);

        if (override.canUpdateBaseline() && originalEvent != null) {
            triggerBaselineUpdate(userId, originalEvent, override);
        }

        if (userId != null && overriddenAction != null) {
            updateAnalysisAction(userId, overriddenAction);
        }
        return override;
    }

    public AdminOverride reject(String requestId, String userId, String adminId,
                                String originalAction, double originalRiskScore, double originalConfidence,
                                String reason) {

        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("Reason is required for admin rejection");
        }

        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("requestId is required");
        }

        AdminOverride override = AdminOverride.builder()
                .overrideId(UUID.randomUUID().toString())
                .requestId(requestId)
                .userId(userId)
                .adminId(adminId)
                .timestamp(Instant.now())
                .originalAction(originalAction)
                .overriddenAction(originalAction)
                .reason(reason)
                .approved(false)
                .originalRiskScore(originalRiskScore)
                .originalConfidence(originalConfidence)
                .build();
        repository.save(override);
        repository.deletePending(requestId);
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

            baselineLearningService.learnIfNormal(userId, adminApprovedDecision, event);

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
            actionRedisRepository.saveAction(userId, ztAction, null);

            if (!ztAction.isBlocking()) {
                actionRedisRepository.removeBlockedFlag(userId);
            }
        } catch (Exception e) {
            log.error("[AdminOverrideService] Redis analysis update failed: userId={}", userId, e);
        }
    }

    public Optional<AdminOverride> findByRequestId(String requestId) {
        return repository.findByRequestId(requestId);
    }

    public boolean isPendingReview(String requestId) {
        return repository.findPending(requestId).isPresent();
    }

    public void addToPendingReview(String requestId, String userId,
                                   double riskScore, double confidence, String reasoning) {
        addToPendingReview(requestId, userId, riskScore, confidence, reasoning, null);
    }

    public void addToPendingReview(String requestId, String userId,
                                   double riskScore, double confidence, String reasoning,
                                   SecurityEvent event) {
        java.util.Map<String, Object> analysisData = new java.util.HashMap<>();
        analysisData.put("riskScore", riskScore);
        analysisData.put("confidence", confidence);
        analysisData.put("reasoning", reasoning);
        analysisData.put("originalAction", ZeroTrustAction.BLOCK.name());

        repository.savePending(requestId, userId, analysisData);

        if (event != null) {
            repository.saveSecurityEvent(requestId, event);
        }
    }

    public Optional<java.util.Map<Object, Object>> getPendingReview(String requestId) {
        return repository.findPending(requestId);
    }

    public Optional<SecurityEvent> getSecurityEvent(String requestId) {
        return repository.findSecurityEvent(requestId);
    }
}
