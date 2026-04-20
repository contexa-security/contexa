package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.Objects;

@Slf4j
public class RedisBlockMfaStateStore implements BlockMfaStateStore {

    private final StringRedisTemplate stringRedisTemplate;
    private final ZeroTrustActionRepository actionRepository;
    private final Duration verifiedTtl;

    private static final Duration DEFAULT_VERIFIED_TTL = Duration.ofHours(1);

    public RedisBlockMfaStateStore(StringRedisTemplate stringRedisTemplate,
                                   ZeroTrustActionRepository actionRepository) {
        this(stringRedisTemplate, actionRepository, DEFAULT_VERIFIED_TTL);
    }

    public RedisBlockMfaStateStore(StringRedisTemplate stringRedisTemplate,
                                   ZeroTrustActionRepository actionRepository,
                                   Duration verifiedTtl) {
        this.stringRedisTemplate = Objects.requireNonNull(stringRedisTemplate, "stringRedisTemplate");
        this.actionRepository = Objects.requireNonNull(actionRepository, "actionRepository");
        this.verifiedTtl = Objects.requireNonNull(verifiedTtl, "verifiedTtl");
    }

    @Override
    public void setVerified(String userId) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaVerified(userId);
            stringRedisTemplate.opsForValue().set(key, "true", verifiedTtl);
        } catch (Exception e) {
            log.error("[BlockMfaStateStore] Failed to set verified: userId={}", userId, e);
        }
    }

    @Override
    public boolean isVerified(String userId) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaVerified(userId);
            return Boolean.parseBoolean(stringRedisTemplate.opsForValue().get(key));
        } catch (Exception e) {
            log.error("[BlockMfaStateStore] Failed to check verified: userId={}", userId, e);
            return false;
        }
    }

    @Override
    public void setPending(String userId) {
        actionRepository.setBlockMfaPending(userId);
    }

    @Override
    public void clearPending(String userId) {
        actionRepository.clearBlockMfaPending(userId);
    }

    @Override
    public int getFailCount(String userId) {
        return (int) actionRepository.getBlockMfaFailCount(userId);
    }
}
