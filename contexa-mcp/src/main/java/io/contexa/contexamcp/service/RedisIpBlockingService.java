package io.contexa.contexamcp.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@RequiredArgsConstructor
public class RedisIpBlockingService extends AbstractIpBlockingService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String BLOCKED_IP_KEY_PREFIX = "blocked:ip:";
    private static final String BLOCKED_IP_SET_KEY = "blocked:ip:set";
    private static final String WHITELIST_IP_KEY = "whitelist:ip:set";

    @Override
    protected boolean doIsWhitelisted(String ipAddress) {
        return Boolean.TRUE.equals(
                redisTemplate.opsForSet().isMember(WHITELIST_IP_KEY, ipAddress)
        );
    }

    @Override
    protected boolean doIsBlocked(String ipAddress) {
        String blockKey = BLOCKED_IP_KEY_PREFIX + ipAddress;
        return Boolean.TRUE.equals(redisTemplate.hasKey(blockKey));
    }

    @Override
    protected void doBlockIp(String ipAddress, BlockedIpInfo info, Duration duration) {
        String blockKey = BLOCKED_IP_KEY_PREFIX + ipAddress;
        if (duration != null) {
            redisTemplate.opsForValue().set(blockKey, info, duration.toSeconds(), TimeUnit.SECONDS);
        } else {
            redisTemplate.opsForValue().set(blockKey, info);
        }
        redisTemplate.opsForSet().add(BLOCKED_IP_SET_KEY, ipAddress);
    }
}
