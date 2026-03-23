package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.soar.event.SecurityActionEvent;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class BlockedUserService implements IBlockedUserRecorder {

    private final BlockedUserJpaRepository blockedUserJpaRepository;
    private final AdminOverrideService adminOverrideService;
    private final ZeroTrustActionRepository actionRedisRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final CentralAuditFacade centralAuditFacade;
    private final BlockingSignalBroadcaster blockingDecisionRegistry;

    @Override
    @Transactional
    public void recordBlock(String requestId, String userId, String username,
                            String action, String reasoning,
                            String sourceIp, String userAgent) {
        int blockCount = blockedUserJpaRepository.countByUserId(userId) + 1;

        Optional<BlockedUser> existingOpt = blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED);

        if (existingOpt.isPresent()) {
            BlockedUser existing = existingOpt.get();
            existing.setRequestId(requestId);
            existing.setRiskScore(null);
            existing.setConfidence(null);
            existing.setReasoning(reasoning);
            existing.setBlockedAt(LocalDateTime.now());
            existing.setBlockCount(blockCount);
            existing.setSourceIp(sourceIp);
            existing.setUserAgent(userAgent);
            blockedUserJpaRepository.save(existing);
        } else {
            BlockedUser blockedUser = BlockedUser.builder()
                    .userId(userId)
                    .username(username)
                    .requestId(requestId)
                    .riskScore(null)
                    .confidence(null)
                    .reasoning(reasoning)
                    .blockedAt(LocalDateTime.now())
                    .blockCount(blockCount)
                    .status(BlockedUserStatus.BLOCKED)
                    .sourceIp(sourceIp)
                    .userAgent(userAgent)
                    .build();
            blockedUserJpaRepository.save(blockedUser);
        }
        // Audit: user blocked
        centralAuditFacade.recordAsync(AuditRecord.builder()
                .eventCategory(AuditEventCategory.USER_BLOCKED)
                .principalName(userId)
                .resourceIdentifier(requestId)
                .eventSource("IAM")
                .clientIp(sourceIp)
                .userAgent(userAgent)
                .action("USER_BLOCKED")
                .decision("BLOCK")
                .outcome("BLOCKED")
                .reason(reasoning)
                .details(Map.of("username", username != null ? username : "",
                        "blockCount", blockedUserJpaRepository.countByUserId(userId)))
                .build());
    }



    @Override
    @Transactional
    public void resolveBlock(String userId, String adminId, String resolvedAction, String reason) {
        Optional<BlockedUser> blockedOpt = blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED);

        if (blockedOpt.isEmpty()) {
            return;
        }

        BlockedUser blocked = blockedOpt.get();
        applyResolution(blocked, adminId, resolvedAction, reason);
    }

    @Transactional
    public void resolveBlockById(Long id, String adminId, String resolvedAction, String reason) {
        BlockedUser blocked = blockedUserJpaRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Blocked user not found: id=" + id));

        if (blocked.getStatus() == BlockedUserStatus.RESOLVED) {
            throw new IllegalStateException("Already resolved: id=" + id);
        }

        applyResolution(blocked, adminId, resolvedAction, reason);

        try {
            SecurityEvent blockEvent = SecurityEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .source(SecurityEvent.EventSource.IAM)
                    .userId(blocked.getUserId())
                    .userName(blocked.getUsername())
                    .sourceIp(blocked.getSourceIp())
                    .userAgent(blocked.getUserAgent())
                    .timestamp(LocalDateTime.now())
                    .description("Admin approved unblock - learning from block context")
                    .build();

            adminOverrideService.approve(
                    blocked.getRequestId(),
                    blocked.getUserId(),
                    adminId,
                    ZeroTrustAction.BLOCK.name(),
                    resolvedAction,
                    reason,
                    blockEvent
            );
        } catch (Exception e) {
            log.error("[BlockedUserService] Failed to sync AdminOverride: requestId={}",
                    blocked.getRequestId(), e);
            clearRedisBlockKeys(blocked.getUserId(), resolvedAction);
        }
    }

    @Transactional
    public void requestUnblock(String userId, String reason) {
        Optional<BlockedUser> blockedOpt = blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED);

        if (blockedOpt.isEmpty()) {
            return;
        }

        BlockedUser blocked = blockedOpt.get();
        blocked.setStatus(BlockedUserStatus.UNBLOCK_REQUESTED);
        blocked.setUnblockRequestedAt(LocalDateTime.now());
        blocked.setUnblockReason(reason);
        blockedUserJpaRepository.save(blocked);

        // Audit: unblock requested
        centralAuditFacade.recordAsync(AuditRecord.builder()
                .eventCategory(AuditEventCategory.UNBLOCK_REQUESTED)
                .principalName(userId)
                .resourceIdentifier(blocked.getRequestId())
                .eventSource("IAM")
                .action("UNBLOCK_REQUESTED")
                .decision("PENDING")
                .outcome("REQUESTED")
                .reason(reason)
                .build());
    }

    @Transactional
    public void requestUnblockWithMfa(String userId, String reason, boolean mfaVerified) {
        Optional<BlockedUser> blockedOpt = blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED);

        if (blockedOpt.isEmpty()) {
            return;
        }

        BlockedUser blocked = blockedOpt.get();
        blocked.setStatus(BlockedUserStatus.UNBLOCK_REQUESTED);
        blocked.setUnblockRequestedAt(LocalDateTime.now());
        blocked.setUnblockReason(reason);
        blocked.setMfaVerified(mfaVerified);
        if (mfaVerified) {
            blocked.setMfaVerifiedAt(LocalDateTime.now());
        }
        blockedUserJpaRepository.save(blocked);
    }

    @Override
    @Transactional
    public void markMfaVerified(String userId) {
        blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED)
                .ifPresent(b -> {
                    b.setMfaVerified(true);
                    b.setMfaVerifiedAt(LocalDateTime.now());
                    blockedUserJpaRepository.save(b);

                    centralAuditFacade.recordAsync(AuditRecord.builder()
                            .eventCategory(AuditEventCategory.MFA_VERIFICATION_SUCCESS)
                            .principalName(userId)
                            .resourceIdentifier(b.getRequestId())
                            .eventSource("IAM")
                            .action("MFA_VERIFIED")
                            .decision("ALLOW")
                            .outcome("VERIFIED")
                            .clientIp(b.getSourceIp())
                            .build());
                });
    }

    @Override
    @Transactional
    public void markMfaFailed(String userId) {
        blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED)
                .ifPresent(b -> {
                    b.setStatus(BlockedUserStatus.MFA_FAILED);
                    blockedUserJpaRepository.save(b);

                    log.error("[BlockedUserService] MFA failed - auto response triggered: userId={}", userId);

                    centralAuditFacade.recordAsync(AuditRecord.builder()
                            .eventCategory(AuditEventCategory.MFA_VERIFICATION_FAILED)
                            .principalName(userId)
                            .resourceIdentifier(b.getRequestId())
                            .eventSource("IAM")
                            .clientIp(b.getSourceIp())
                            .action("MFA_FAILED")
                            .decision("BLOCK")
                            .outcome("MFA_FAILED")
                            .reason("MFA authentication failed for blocked user")
                            .riskScore(b.getRiskScore() != null ? b.getRiskScore() : 0.95)
                            .build());

                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("severity", "HIGH");
                    metadata.put("threatType", "ACCOUNT_TAKEOVER_CONTAINMENT");
                    metadata.put("zeroTrustAction", ZeroTrustAction.BLOCK.name());
                    metadata.put("securityEventType", "BLOCKED_USER_MFA_FAILED");
                    metadata.put("allowedTools", List.of("session_termination", "ip_blocking"));
                    metadata.put("incidentId", b.getRequestId());
                    metadata.put("sessionId", b.getRequestId());

                    SecurityActionEvent event = SecurityActionEvent.builder()
                            .eventId(UUID.randomUUID().toString())
                            .actionType(SecurityActionEvent.ActionType.SOAR_AUTO_RESPONSE)
                            .userId(userId)
                            .sourceIp(b.getSourceIp())
                            .reason("MFA authentication failed for blocked user")
                            .triggeredBy("BlockedUserService")
                            .metadata(metadata)
                            .build();

                    eventPublisher.publishEvent(event);
                });
    }

    @Transactional(readOnly = true)
    public List<BlockedUser> getUnblockRequested() {
        return blockedUserJpaRepository.findByStatusOrderByBlockedAtDesc(BlockedUserStatus.UNBLOCK_REQUESTED);
    }

    @Transactional(readOnly = true)
    public List<BlockedUser> getBlockedUsers() {
        return blockedUserJpaRepository.findByStatusOrderByBlockedAtDesc(BlockedUserStatus.BLOCKED);
    }

    @Transactional(readOnly = true)
    public List<BlockedUser> getAllBlockHistory() {
        return blockedUserJpaRepository.findAllByOrderByBlockedAtDesc();
    }

    @Transactional(readOnly = true)
    public Optional<BlockedUser> getBlockDetail(Long id) {
        return blockedUserJpaRepository.findById(id);
    }

    @Transactional
    public void deleteBlockRecord(Long id) {
        BlockedUser blocked = blockedUserJpaRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Blocked user not found: id=" + id));

        if (blocked.getStatus() == BlockedUserStatus.BLOCKED) {
            throw new IllegalStateException("Cannot delete active block. Resolve first: id=" + id);
        }

        blockedUserJpaRepository.delete(blocked);
    }

    private void applyResolution(BlockedUser blocked, String adminId,
                                 String resolvedAction, String reason) {
        blocked.setResolvedAt(LocalDateTime.now());
        blocked.setResolvedBy(adminId);
        blocked.setResolvedAction(resolvedAction);
        blocked.setResolveReason(reason);
        blocked.setStatus(BlockedUserStatus.RESOLVED);
        blockedUserJpaRepository.save(blocked);
    }

    private void clearRedisBlockKeys(String userId, String resolvedAction) {
        try {
            actionRedisRepository.removeBlockedFlag(userId);
            if (blockingDecisionRegistry != null) {
                blockingDecisionRegistry.registerUnblock(userId);
            }
            ZeroTrustAction action = ZeroTrustAction.fromString(resolvedAction);
            actionRedisRepository.saveAction(userId, action, null);
        } catch (Exception e) {
            log.error("[BlockedUserService] Failed to clear Redis block keys: userId={}", userId, e);
        }
    }
}


