package io.contexa.contexaidentity.security.token.store;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Slf4j
public class RedisRefreshTokenStore extends AbstractRefreshTokenStore {

    private static final String TOKEN_KEY_PREFIX = "refresh_token:";
    private static final String USER_DEVICES_KEY_PREFIX = "user:devices:";
    private static final String BLACKLIST_TOKEN_KEY = "blacklist:token";
    private static final String BLACKLIST_DEVICE_KEY = "blacklist:device";

    private final StringRedisTemplate redisTemplate;

    private static final String SAVE_TOKEN_SCRIPT =
            "local tokenKey = KEYS[1] " +
                    "local devicesKey = KEYS[2] " +
                    "local username = ARGV[1] " +
                    "local expiration = ARGV[2] " +
                    "local token = ARGV[3] " +
                    "local deviceId = ARGV[4] " +
                    "local ttl = ARGV[5] " +
                    "redis.call('hset', tokenKey, 'username', username, 'expiration', expiration, 'token', token) " +
                    "redis.call('expire', tokenKey, ttl) " +
                    "redis.call('zadd', devicesKey, redis.call('time')[1], deviceId) " +
                    "return 1";

    private static final String REMOVE_TOKEN_SCRIPT =
            "local tokenKey = KEYS[1] " +
                    "local devicesKey = KEYS[2] " +
                    "local deviceId = ARGV[1] " +
                    "redis.call('del', tokenKey) " +
                    "redis.call('zrem', devicesKey, deviceId) " +
                    "return 1";

    public RedisRefreshTokenStore(StringRedisTemplate redisTemplate,
                                  JwtDecoder jwtDecoder,
                                  AuthContextProperties props,
                                  RedisDistributedLockService lockService) {
        super(jwtDecoder, props);
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected void doSaveToken(String username, String deviceId, String token, Instant expiration) {
        String tokenKey = TOKEN_KEY_PREFIX + deviceKey(username, deviceId);
        String devicesKey = USER_DEVICES_KEY_PREFIX + username;
        long ttlSeconds = calculateTtlSeconds(expiration);

        if (ttlSeconds <= 0) {
            log.warn("Token TTL is non-positive, not saving. User: {}, deviceId: {}", username, deviceId);
            return;
        }

        redisTemplate.execute(
                new DefaultRedisScript<>(SAVE_TOKEN_SCRIPT, Long.class),
                Arrays.asList(tokenKey, devicesKey),
                username,
                String.valueOf(expiration.toEpochMilli()),
                token,
                deviceId,
                String.valueOf(ttlSeconds)
        );
    }

    @Override
    protected TokenInfo doGetTokenInfo(String username, String deviceId) {
        String tokenKey = TOKEN_KEY_PREFIX + deviceKey(username, deviceId);

        Map<Object, Object> entries = redisTemplate.opsForHash().entries(tokenKey);
        if (entries.isEmpty()) {
            return null;
        }

        String storedUsername = (String) entries.get("username");
        String expirationStr = (String) entries.get("expiration");

        if (storedUsername == null || expirationStr == null) {
            return null;
        }

        Instant expiration = Instant.ofEpochMilli(Long.parseLong(expirationStr));
        return new TokenInfo(storedUsername, expiration);
    }

    @Override
    protected void doRemoveToken(String username, String deviceId) {
        String tokenKey = TOKEN_KEY_PREFIX + deviceKey(username, deviceId);
        String devicesKey = USER_DEVICES_KEY_PREFIX + username;

        redisTemplate.execute(
                new DefaultRedisScript<>(REMOVE_TOKEN_SCRIPT, Long.class),
                Arrays.asList(tokenKey, devicesKey),
                deviceId
        );
    }

    @Override
    protected void doBlacklistToken(String token, String username, Instant expiration, String reason) {
        long ttlSeconds = calculateTtlSeconds(expiration);

        if (ttlSeconds > 0) {
            redisTemplate.opsForSet().add(BLACKLIST_TOKEN_KEY, token);

            String infoKey = BLACKLIST_TOKEN_KEY + ":" + token;
            redisTemplate.opsForHash().put(infoKey, "username", username);
            redisTemplate.opsForHash().put(infoKey, "reason", reason);
            redisTemplate.opsForHash().put(infoKey, "timestamp", String.valueOf(System.currentTimeMillis()));
            redisTemplate.expire(infoKey, ttlSeconds, TimeUnit.SECONDS);
        }
    }

    @Override
    protected void doBlacklistDevice(String username, String deviceId, String reason) {
        String key = deviceKey(username, deviceId);
        redisTemplate.opsForSet().add(BLACKLIST_DEVICE_KEY, key);

        String infoKey = BLACKLIST_DEVICE_KEY + ":" + key;
        redisTemplate.opsForHash().put(infoKey, "username", username);
        redisTemplate.opsForHash().put(infoKey, "deviceId", deviceId);
        redisTemplate.opsForHash().put(infoKey, "reason", reason);
        redisTemplate.opsForHash().put(infoKey, "timestamp", String.valueOf(System.currentTimeMillis()));
    }

    @Override
    protected Iterable<String> doGetUserDevices(String username) {
        String devicesKey = USER_DEVICES_KEY_PREFIX + username;
        Set<String> devices = redisTemplate.opsForZSet().range(devicesKey, 0, -1);
        return devices != null ? devices : Collections.emptySet();
    }

    @Override
    protected int doGetUserDeviceCount(String username) {
        String devicesKey = USER_DEVICES_KEY_PREFIX + username;
        Long count = redisTemplate.opsForZSet().zCard(devicesKey);
        return count != null ? count.intValue() : 0;
    }

    @Override
    protected String doGetOldestDevice(String username) {
        String devicesKey = USER_DEVICES_KEY_PREFIX + username;
        Set<String> oldest = redisTemplate.opsForZSet().range(devicesKey, 0, 0);
        return (oldest != null && !oldest.isEmpty()) ? oldest.iterator().next() : null;
    }

    @Override
    public boolean isBlacklisted(String token) {
        if (token == null) {
            return false;
        }

        if (Boolean.TRUE.equals(redisTemplate.opsForSet().isMember(BLACKLIST_TOKEN_KEY, token))) {
            return true;
        }

        try {
            Jwt jwt = jwtDecoder.decode(token);

            String subject = jwt.getSubject();
            String deviceId = jwt.getClaim("deviceId");
            if (deviceId == null) {
                return false;
            }

            String deviceKey = deviceKey(subject, deviceId);
            return Boolean.TRUE.equals(
                    redisTemplate.opsForSet().isMember(BLACKLIST_DEVICE_KEY, deviceKey)
            );

        } catch (JwtException e) {
            return false;
        } catch (Exception e) {
            log.error("Unexpected error during isBlacklisted check. Error: {}", e.getMessage(), e);
            return false;
        }
    }

    private long calculateTtlSeconds(Instant expiration) {
        return Math.max(0, expiration.toEpochMilli() / 1000 - Instant.now().toEpochMilli() / 1000);
    }
}
