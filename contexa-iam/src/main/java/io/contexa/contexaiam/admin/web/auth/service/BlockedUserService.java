package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class BlockedUserService implements IBlockedUserRecorder {

    private final BlockedUserJpaRepository blockedUserJpaRepository;
    private final AdminOverrideService adminOverrideService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final StringRedisTemplate stringRedisTemplate;

    @Override
    @Transactional
    public void recordBlock(String requestId, String userId, String username,
                            double riskScore, double confidence, String reasoning,
                            String sourceIp, String userAgent) {
        int blockCount = blockedUserJpaRepository.countByUserId(userId) + 1;

        BlockedUser blockedUser = BlockedUser.builder()
                .userId(userId)
                .username(username)
                .requestId(requestId)
                .riskScore(riskScore)
                .confidence(confidence)
                .reasoning(reasoning)
                .blockedAt(LocalDateTime.now())
                .blockCount(blockCount)
                .status(BlockedUserStatus.BLOCKED)
                .sourceIp(sourceIp)
                .userAgent(userAgent)
                .build();

        blockedUserJpaRepository.save(blockedUser);
    }

    @Override
    @Transactional
    public void resolveBlock(String userId, String adminId, String resolvedAction, String reason) {
        Optional<BlockedUser> blockedOpt = blockedUserJpaRepository
                .findByUserIdAndStatus(userId, BlockedUserStatus.BLOCKED);

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

        if (blocked.getStatus() != BlockedUserStatus.BLOCKED) {
            throw new IllegalStateException("Already resolved: id=" + id);
        }

        applyResolution(blocked, adminId, resolvedAction, reason);

        try {
            adminOverrideService.approve(
                    blocked.getRequestId(),
                    blocked.getUserId(),
                    adminId,
                    ZeroTrustAction.BLOCK.name(),
                    blocked.getRiskScore() != null ? blocked.getRiskScore() : 0.0,
                    blocked.getConfidence() != null ? blocked.getConfidence() : 0.0,
                    resolvedAction,
                    reason,
                    adminOverrideService.getSecurityEvent(blocked.getRequestId()).orElse(null)
            );
        } catch (Exception e) {
            log.error("[BlockedUserService] Failed to sync AdminOverride: requestId={}",
                    blocked.getRequestId(), e);
            clearRedisBlockKeys(blocked.getUserId(), resolvedAction);
        }
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
            String userBlockedKey = ZeroTrustRedisKeys.userBlocked(userId);
            redisTemplate.delete(userBlockedKey);

            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            redisTemplate.opsForHash().put(analysisKey, "action", resolvedAction);
            redisTemplate.expire(analysisKey, Duration.ofSeconds(30));

            String lastActionKey = ZeroTrustRedisKeys.hcadLastVerifiedAction(userId);
            stringRedisTemplate.opsForValue().set(lastActionKey, resolvedAction, Duration.ofHours(24));
        } catch (Exception e) {
            log.error("[BlockedUserService] Failed to clear Redis block keys: userId={}", userId, e);
        }
    }
}
