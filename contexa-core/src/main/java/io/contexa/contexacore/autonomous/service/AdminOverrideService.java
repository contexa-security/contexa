package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.saas.DecisionFeedbackForwardingService;
import io.contexa.contexacore.autonomous.saas.ThreatOutcomeForwardingService;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
public class AdminOverrideService {

    private final SecurityLearningService securityLearningService;
    private final ZeroTrustActionRepository actionRedisRepository;
    private final DistributedLockService lockService;
    private final CentralAuditFacade centralAuditFacade;
    private final DecisionFeedbackForwardingService decisionFeedbackForwardingService;
    private final ThreatOutcomeForwardingService threatOutcomeForwardingService;
    private final BlockingSignalBroadcaster blockingSignalBroadcaster;

    private static final String BASELINE_LOCK_PREFIX = "baseline:update:";
    private static final Duration BASELINE_LOCK_TIMEOUT = Duration.ofSeconds(10);

    public AdminOverrideService(SecurityLearningService securityLearningService,
                                ZeroTrustActionRepository actionRedisRepository,
                                DistributedLockService lockService, CentralAuditFacade centralAuditFacade,
                                DecisionFeedbackForwardingService decisionFeedbackForwardingService,
                                ThreatOutcomeForwardingService threatOutcomeForwardingService, BlockingSignalBroadcaster blockingSignalBroadcaster) {
        this.securityLearningService = securityLearningService;
        this.actionRedisRepository = actionRedisRepository;
        this.lockService = lockService;
        this.centralAuditFacade = centralAuditFacade;
        this.decisionFeedbackForwardingService = decisionFeedbackForwardingService;
        this.threatOutcomeForwardingService = threatOutcomeForwardingService;
        this.blockingSignalBroadcaster = blockingSignalBroadcaster;
    }

    public AdminOverride approve(String requestId, String userId, String adminId,
                                 String originalAction,
                                 String overriddenAction, String reason,
                                 SecurityEvent originalEvent) {
        return approve(
                requestId,
                userId,
                adminId,
                originalAction,
                Double.NaN,
                Double.NaN,
                overriddenAction,
                reason,
                originalEvent
        );
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

        auditAdminOverride(override, originalEvent);
        captureDecisionFeedback(override, originalEvent);
        captureThreatOutcome(override, originalEvent);
        return override;
    }

    private void captureDecisionFeedback(AdminOverride override, SecurityEvent originalEvent) {
        if (decisionFeedbackForwardingService == null) {
            return;
        }
        try {
            decisionFeedbackForwardingService.capture(override, originalEvent);
        }
        catch (Exception e) {
            log.error("[AdminOverrideService] Decision feedback forwarding failed: requestId={}, overrideId={}",
                    override.getRequestId(), override.getOverrideId(), e);
        }
    }

    private void captureThreatOutcome(AdminOverride override, SecurityEvent originalEvent) {
        if (threatOutcomeForwardingService == null) {
            return;
        }
        try {
            threatOutcomeForwardingService.capture(override, originalEvent);
        }
        catch (Exception e) {
            log.error("[AdminOverrideService] Threat outcome forwarding failed: requestId={}, overrideId={}",
                    override.getRequestId(), override.getOverrideId(), e);
        }
    }

    private void triggerBaselineUpdate(String userId, SecurityEvent event, AdminOverride override) {
        try {
            SecurityDecision adminApprovedDecision = SecurityDecision.builder()
                    .action(ZeroTrustAction.ALLOW)
                    .riskScore(0.0)
                    .confidence(0.95)
                    .reasoning("Admin approved: " + override.getReason())
                    .analysisTime(System.currentTimeMillis())
                    .build();

            if (lockService != null) {
                lockService.executeWithLock(
                        BASELINE_LOCK_PREFIX + userId,
                        BASELINE_LOCK_TIMEOUT,
                        () -> {
                            securityLearningService.learnAndStore(userId, adminApprovedDecision, event);
                            return null;
                        });
            } else {
                securityLearningService.learnAndStore(userId, adminApprovedDecision, event);
            }

        } catch (Exception e) {
            log.error("[AdminOverrideService] Baseline update failed: userId={}, overrideId={}",
                    userId, override.getOverrideId(), e);
        }
    }

    private void auditAdminOverride(AdminOverride override, SecurityEvent originalEvent) {
        if (centralAuditFacade == null) {
            return;
        }
        try {
            Map<String, Object> details = new HashMap<>();
            details.put("overrideId", override.getOverrideId());
            details.put("requestId", override.getRequestId());
            details.put("originalAction", override.getOriginalAction());
            details.put("overriddenAction", override.getOverriddenAction());
            details.put("originalRiskScore", override.getOriginalRiskScore());
            details.put("originalConfidence", override.getOriginalConfidence());
            details.put("baselineUpdated", override.canUpdateBaseline());

            String sourceIp = null;
            if (originalEvent != null) {
                sourceIp = originalEvent.getSourceIp();
            }

            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.ADMIN_OVERRIDE)
                    .principalName(override.getAdminId())
                    .eventSource("CORE")
                    .clientIp(sourceIp)
                    .resourceIdentifier(override.getUserId())
                    .action(override.isApproved() ? "APPROVE" : "DENY")
                    .decision(override.getOverriddenAction())
                    .reason(override.getReason())
                    .outcome(override.isApproved() ? "APPROVED" : "DENIED")
                    .riskScore(override.getOriginalRiskScore())
                    .details(details)
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit admin override: overrideId={}", override.getOverrideId(), e);
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
                if (blockingSignalBroadcaster != null) {
                    blockingSignalBroadcaster.registerUnblock(userId);
                }
            } else {
                actionRedisRepository.saveAction(userId, ztAction, null);
            }
        } catch (Exception e) {
            log.error("[AdminOverrideService] Redis analysis update failed: userId={}", userId, e);
        }
    }

}
