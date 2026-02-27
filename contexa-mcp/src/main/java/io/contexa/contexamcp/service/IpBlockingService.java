package io.contexa.contexamcp.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
public class IpBlockingService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String BLOCKED_IP_KEY_PREFIX = "blocked:ip:";
    private static final String BLOCKED_IP_SET_KEY = "blocked:ip:set";
    private static final String WHITELIST_IP_KEY = "whitelist:ip:set";

    public BlockResult blockIp(String ipAddress, String reason, Duration duration, String blockedBy) {
        try {

            if (isWhitelisted(ipAddress)) {
                log.error("Cannot block whitelisted IP: {}", ipAddress);
                return BlockResult.builder()
                    .success(false)
                    .ipAddress(ipAddress)
                    .message("IP is whitelisted and cannot be blocked")
                    .build();
            }

            if (isBlocked(ipAddress)) {
                return BlockResult.builder()
                    .success(false)
                    .ipAddress(ipAddress)
                    .message("IP is already blocked")
                    .build();
            }

            BlockedIpInfo blockInfo = BlockedIpInfo.builder()
                .ipAddress(ipAddress)
                .reason(reason)
                .blockedAt(Instant.now())
                .expiresAt(duration != null ? Instant.now().plus(duration) : null)
                .blockedBy(blockedBy)
                .active(true)
                .build();

            String blockKey = BLOCKED_IP_KEY_PREFIX + ipAddress;
            if (duration != null) {
                redisTemplate.opsForValue().set(blockKey, blockInfo, duration.toSeconds(), TimeUnit.SECONDS);
            } else {
                redisTemplate.opsForValue().set(blockKey, blockInfo);
            }

            redisTemplate.opsForSet().add(BLOCKED_IP_SET_KEY, ipAddress);

            return BlockResult.builder()
                .success(true)
                .ipAddress(ipAddress)
                .message("IP successfully blocked")
                .blockedUntil(blockInfo.getExpiresAt())
                .build();

        } catch (Exception e) {
            log.error("Failed to block IP: {}", ipAddress, e);
            return BlockResult.builder()
                .success(false)
                .ipAddress(ipAddress)
                .message("Failed to block IP: " + e.getMessage())
                .build();
        }
    }

    private boolean isBlocked(String ipAddress) {
        String blockKey = BLOCKED_IP_KEY_PREFIX + ipAddress;
        return Boolean.TRUE.equals(redisTemplate.hasKey(blockKey));
    }

    private boolean isWhitelisted(String ipAddress) {
        return Boolean.TRUE.equals(
            redisTemplate.opsForSet().isMember(WHITELIST_IP_KEY, ipAddress)
        );
    }

    @Data
    @Builder
    public static class BlockResult {
        private boolean success;
        private String ipAddress;
        private String message;
        private Instant blockedUntil;
    }

    @Data
    @Builder
    public static class BlockedIpInfo implements Serializable {
        private String ipAddress;
        private String reason;
        private Instant blockedAt;
        private Instant expiresAt;
        private String blockedBy;
        private boolean active;
    }
}
