package io.contexa.contexaidentity.security.token.store;

import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.management.EnhancedRefreshTokenStore;
import io.contexa.contexaidentity.security.token.management.RefreshTokenAnomalyDetector;
import io.contexa.contexaidentity.security.token.management.RefreshTokenManagementService;
import io.contexa.contexaidentity.security.token.management.TokenChainManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;


@Slf4j
public class RedisRefreshTokenStore extends AbstractRefreshTokenStore implements EnhancedRefreshTokenStore {

    private static final String TOKEN_KEY_PREFIX = "refresh_token:";
    private static final String USER_DEVICES_KEY_PREFIX = "user:devices:";
    private static final String BLACKLIST_TOKEN_KEY = "blacklist:token";
    private static final String BLACKLIST_DEVICE_KEY = "blacklist:device";
    private static final String LOCK_KEY_PREFIX = "token:lock:";
    private static final String TOKEN_USAGE_PREFIX = "token:usage:";
    private static final String TOKEN_METADATA_PREFIX = "token:metadata:";

    private final StringRedisTemplate redisTemplate;
    private final RedisDistributedLockService lockService;
    private final RedisEventPublisher eventPublisher;

    
    private final TokenChainManager tokenChainManager;
    private final RefreshTokenAnomalyDetector anomalyDetector;
    private final RefreshTokenManagementService managementService;
    private final boolean enhancedSecurityEnabled;

    
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
                                  AuthContextProperties props) {
        this(redisTemplate, jwtDecoder, props, null, null, null, null, null);
    }

    
    public RedisRefreshTokenStore(StringRedisTemplate redisTemplate,
                                  JwtDecoder jwtDecoder,
                                  AuthContextProperties props,
                                  RedisDistributedLockService lockService,
                                  RedisEventPublisher eventPublisher) {
        this(redisTemplate, jwtDecoder, props, lockService, eventPublisher, null, null, null);
    }

    
    public RedisRefreshTokenStore(StringRedisTemplate redisTemplate,
                                  JwtDecoder jwtDecoder,
                                  AuthContextProperties props,
                                  RedisDistributedLockService lockService,
                                  RedisEventPublisher eventPublisher,
                                  TokenChainManager tokenChainManager,
                                  RefreshTokenAnomalyDetector anomalyDetector,
                                  RefreshTokenManagementService managementService) {
        super(jwtDecoder, props);
        this.redisTemplate = redisTemplate;
        this.lockService = lockService;
        this.eventPublisher = eventPublisher;
        this.tokenChainManager = tokenChainManager;
        this.anomalyDetector = anomalyDetector;
        this.managementService = managementService;

        
        this.enhancedSecurityEnabled = tokenChainManager != null || anomalyDetector != null;

        log.info("RedisRefreshTokenStore initialized. Enhanced security: {}", enhancedSecurityEnabled);
    }

    @Override
    public void save(String refreshToken, String username) {
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");
        Objects.requireNonNull(username, "username cannot be null");

        
        if (enhancedSecurityEnabled && anomalyDetector != null) {
            String deviceId = extractDeviceId(refreshToken);
            ClientInfo clientInfo = getCurrentClientInfo();
            AnomalyDetectionResult anomaly = anomalyDetector.detectAnomaly(username, deviceId, clientInfo);

            
            if (anomaly.isAnomalous() && isCriticalAnomalyType(anomaly.type())) {
                log.error("Critical anomaly detected for user: {}. Type: {}, Score: {}",
                        username, anomaly.type(), anomaly.riskScore());
                throw new SecurityException("Token save rejected due to security risk");
            }
        }

        String lockKey = LOCK_KEY_PREFIX + username;

        
        if (lockService != null) {
            try {
                lockService.executeWithLock(lockKey, Duration.ofSeconds(5), () -> {
                    doSaveWithEnhancements(refreshToken, username);
                    return null;
                });
            } catch (RedisDistributedLockService.LockAcquisitionException e) {
                log.error("Failed to acquire lock for saving token. User: {}", username, e);
                throw new RuntimeException("Token save failed due to lock acquisition failure", e);
            }
        } else {
            doSaveWithEnhancements(refreshToken, username);
        }
    }

    
    private void doSaveWithEnhancements(String refreshToken, String username) {
        
        super.save(refreshToken, username);

        
        if (enhancedSecurityEnabled && tokenChainManager != null) {
            String deviceId = extractDeviceId(refreshToken);
            tokenChainManager.startNewChain(refreshToken, username, deviceId);
        }

        
        if (enhancedSecurityEnabled) {
            recordUsage(refreshToken, TokenAction.CREATED, getCurrentClientInfo());
        }


        if (managementService != null) {
            managementService.updateTokenStatistics(username, "ISSUED");
        }
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

        
        publishTokenSavedEvent(username, deviceId);

        
        if (enhancedSecurityEnabled) {
            saveTokenMetadata(token, username, deviceId, expiration);
        }
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

        
        publishTokenRemovedEvent(username, deviceId);
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
            log.trace("JWT decoding failed during isBlacklisted check. Error: {}", e.getMessage(), e);
            return false;
        } catch (Exception e) {
            log.error("Unexpected error during isBlacklisted check. Error: {}", e.getMessage(), e);
            return false;
        }
    }

    

    @Override
    public void rotate(String oldToken, String newToken, String username, String deviceId, ClientInfo clientInfo) {
        if (!enhancedSecurityEnabled) {
            
            remove(oldToken);
            save(newToken, username);
            return;
        }

        
        if (tokenChainManager != null && tokenChainManager.isTokenUsed(oldToken)) {
            log.error("Token reuse attack detected! Token: {}, User: {}", oldToken, username);
            revokeAllUserTokens(username, "Token reuse detected");
            throw new TokenChainManager.TokenReuseException("Token has already been used");
        }

        
        if (anomalyDetector != null) {
            AnomalyDetectionResult anomaly = anomalyDetector.detectAnomaly(username, deviceId, clientInfo);

            if (anomaly.isAnomalous()) {
                log.warn("Anomaly detected during token rotation. User: {}, Type: {}",
                        username, anomaly.type());
            }
        }

        
        if (tokenChainManager != null) {
            tokenChainManager.rotateToken(oldToken, newToken, username, deviceId);
        }

        
        remove(oldToken);
        save(newToken, username);

        
        recordUsage(oldToken, TokenAction.ROTATED, clientInfo);
        recordUsage(newToken, TokenAction.CREATED, clientInfo);

        
        if (managementService != null) {
            managementService.updateTokenStatistics(username, "REFRESHED");
        }
    }

    @Override
    public void recordUsage(String token, TokenAction action, ClientInfo clientInfo) {
        if (!enhancedSecurityEnabled) {
            return;
        }

        String key = TOKEN_USAGE_PREFIX + token;

        
        String username = "unknown";
        try {
            
            Jwt jwt = jwtDecoder.decode(token);
            username = jwt.getSubject(); 
        } catch (Exception e) {
            log.trace("Failed to extract username from token for usage recording. Error: {}", e.getMessage(), e);
        }

        Map<String, String> usage = new HashMap<>();
        usage.put("username", username); 
        usage.put("action", action.name());
        usage.put("timestamp", Instant.now().toString());
        usage.put("ip", clientInfo.ipAddress());
        usage.put("userAgent", clientInfo.userAgent());
        usage.put("location", clientInfo.location());

        redisTemplate.opsForHash().putAll(key, usage);
        redisTemplate.expire(key, 30, TimeUnit.DAYS);

        log.debug("Token usage recorded: {} - {} for user: {}", token, action, username);
    }

    @Override
    public boolean isTokenReused(String token) {
        return enhancedSecurityEnabled && tokenChainManager != null && tokenChainManager.isTokenUsed(token);
    }

    @Override
    public AnomalyDetectionResult detectAnomaly(String username, String deviceId, ClientInfo clientInfo) {
        if (!enhancedSecurityEnabled || anomalyDetector == null) {
            return new AnomalyDetectionResult(false, AnomalyType.NONE, "Anomaly detection disabled", 0.0);
        }
        return anomalyDetector.detectAnomaly(username, deviceId, clientInfo);
    }

    @Override
    public void revokeAllUserTokens(String username, String reason) {
        log.info("Revoking all tokens for user: {}, reason: {}", username, reason);

        
        for (String deviceId : doGetUserDevices(username)) {
            doRemoveToken(username, deviceId);
            blacklistDevice(username, deviceId, reason);
        }

        
        publishTokenRevokedEvent(username, null, reason);

        
        if (managementService != null) {
            managementService.updateTokenStatistics(username, "REVOKED");
        }
    }

    @Override
    public void revokeDeviceTokens(String username, String deviceId, String reason) {
        log.info("Revoking tokens for user: {}, device: {}, reason: {}",
                username, deviceId, reason);

        doRemoveToken(username, deviceId);
        blacklistDevice(username, deviceId, reason);

        
        publishTokenRevokedEvent(username, deviceId, reason);

        
        if (managementService != null) {
            managementService.updateTokenStatistics(username, "REVOKED");
        }
    }

    @Override
    public List<TokenUsageHistory> getTokenHistory(String username, int limit) {
        if (!enhancedSecurityEnabled) {
            return Collections.emptyList();
        }

        
        
        
        
        
        log.warn("Using keys() for token history - not recommended for production. Consider using scan() or indexed structure.");

        
        String pattern = TOKEN_USAGE_PREFIX + "*";
        Set<String> keys = redisTemplate.keys(pattern);

        List<TokenUsageHistory> history = new ArrayList<>();

        if (keys != null) {
            for (String key : keys) {
                Map<Object, Object> data = redisTemplate.opsForHash().entries(key);
                if (username.equals(data.get("username"))) {
                    history.add(mapToTokenUsageHistory(key, data));
                }
            }
        }

        
        return history.stream()
                .sorted((a, b) -> b.timestamp().compareTo(a.timestamp()))
                .limit(limit)
                .collect(Collectors.toList());
    }

    @Override
    public List<ActiveSession> getActiveSessions(String username) {
        List<ActiveSession> sessions = new ArrayList<>();

        for (String deviceId : doGetUserDevices(username)) {
            TokenInfo tokenInfo = doGetTokenInfo(username, deviceId);
            if (tokenInfo != null) {
                sessions.add(createActiveSession(username, deviceId, tokenInfo));
            }
        }

        return sessions;
    }

    @Override
    public Optional<TokenMetadata> getTokenMetadata(String token) {
        if (!enhancedSecurityEnabled) {
            return Optional.empty();
        }

        String key = TOKEN_METADATA_PREFIX + token;
        Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

        if (data.isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(mapToTokenMetadata(data));
    }

    

    private long calculateTtlSeconds(Instant expiration) {
        return Math.max(0, expiration.toEpochMilli() / 1000 - Instant.now().toEpochMilli() / 1000);
    }

    private void publishTokenSavedEvent(String username, String deviceId) {
        if (eventPublisher == null) {
            log.trace("RedisEventPublisher not available, skipping event publication");
            return;
        }

        Map<String, Object> data = new HashMap<>();
        data.put("deviceId", deviceId);
        eventPublisher.publishAuthenticationEvent("TOKEN_SAVED", username, data);
    }

    private void publishTokenRemovedEvent(String username, String deviceId) {
        if (eventPublisher == null) {
            log.trace("RedisEventPublisher not available, skipping event publication");
            return;
        }

        Map<String, Object> data = new HashMap<>();
        data.put("deviceId", deviceId);
        eventPublisher.publishAuthenticationEvent("TOKEN_REMOVED", username, data);
    }

    private void publishTokenRevokedEvent(String username, String deviceId, String reason) {
        if (eventPublisher == null) {
            return;
        }

        Map<String, Object> data = new HashMap<>();
        data.put("reason", reason);
        if (deviceId != null) {
            data.put("deviceId", deviceId);
        }
        eventPublisher.publishSecurityEvent("TOKEN_REVOKED", username, "0.0.0.0", data);
    }

    private String extractDeviceId(String token) {
        try {
            
            Jwt jwt = jwtDecoder.decode(token);
            String deviceId = jwt.getClaim("deviceId");
            return deviceId != null ? deviceId : "unknown";
        } catch (Exception e) {
            log.trace("Failed to extract deviceId from token. Error: {}", e.getMessage(), e);
            return "unknown";
        }
    }

    
    private boolean isCriticalAnomalyType(AnomalyType type) {
        if (type == null) return false;
        return switch (type) {
            case REUSED_TOKEN, GEOGRAPHIC_ANOMALY, DEVICE_MISMATCH, RAPID_REFRESH -> true;
            default -> false;
        };
    }

    
    private ClientInfo getCurrentClientInfo() {
        log.trace("Using dummy ClientInfo - actual HTTP request extraction not implemented");
        return new ClientInfo(
                "127.0.0.1",
                "Mozilla/5.0",
                "device-fingerprint",
                "Seoul, KR",
                Instant.now()
        );
    }

    private void saveTokenMetadata(String token, String username, String deviceId, Instant expiration) {
        String key = TOKEN_METADATA_PREFIX + token;

        Map<String, String> metadata = new HashMap<>();
        metadata.put("username", username);
        metadata.put("deviceId", deviceId);
        metadata.put("issuedAt", Instant.now().toString());
        metadata.put("expiresAt", expiration.toString());
        metadata.put("lastUsedAt", Instant.now().toString());
        metadata.put("usageCount", "1");
        metadata.put("isActive", "true");

        redisTemplate.opsForHash().putAll(key, metadata);
        redisTemplate.expire(key, calculateTtlSeconds(expiration), TimeUnit.SECONDS);
    }

    private TokenUsageHistory mapToTokenUsageHistory(String key, Map<Object, Object> data) {
        return new TokenUsageHistory(
                key.replace(TOKEN_USAGE_PREFIX, ""),
                TokenAction.valueOf((String) data.get("action")),
                new ClientInfo(
                        (String) data.get("ip"),
                        (String) data.get("userAgent"),
                        null,
                        (String) data.get("location"),
                        Instant.parse((String) data.get("timestamp"))
                ),
                Instant.parse((String) data.get("timestamp")),
                true
        );
    }

    private ActiveSession createActiveSession(String username, String deviceId, TokenInfo tokenInfo) {
        return new ActiveSession(
                deviceId,
                "Device " + deviceId,
                "127.0.0.1",
                "Seoul, KR",
                Instant.now(),
                tokenInfo.getExpiration().minusSeconds(7 * 24 * 60 * 60), 
                false
        );
    }

    private TokenMetadata mapToTokenMetadata(Map<Object, Object> data) {
        return new TokenMetadata(
                (String) data.get("username"),
                (String) data.get("deviceId"),
                Instant.parse((String) data.get("issuedAt")),
                Instant.parse((String) data.get("expiresAt")),
                Instant.parse((String) data.get("lastUsedAt")),
                Integer.parseInt((String) data.getOrDefault("usageCount", "0")),
                (String) data.get("tokenChainId"),
                Boolean.parseBoolean((String) data.getOrDefault("isActive", "true"))
        );
    }
}