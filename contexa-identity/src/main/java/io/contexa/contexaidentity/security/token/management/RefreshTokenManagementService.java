package io.contexa.contexaidentity.security.token.management;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;


@Slf4j
public class RefreshTokenManagementService {

    private static final String STATS_KEY_PREFIX = "token:stats:";
    private static final String AUDIT_LOG_PREFIX = "token:audit:";
    private static final String SESSION_KEY_PREFIX = "token:session:";

    private final StringRedisTemplate redisTemplate;
    private final RedisEventPublisher eventPublisher;
    private final EnhancedRefreshTokenStore enhancedTokenStore;
    private final ObjectMapper objectMapper;

    public RefreshTokenManagementService(StringRedisTemplate redisTemplate, RedisEventPublisher eventPublisher, EnhancedRefreshTokenStore tokenStore, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.eventPublisher = eventPublisher;
        this.enhancedTokenStore = tokenStore;
        this.objectMapper = objectMapper;
    }

    
    public UserTokenDashboard getUserTokenDashboard(String username) {
        
        List<EnhancedRefreshTokenStore.ActiveSession> activeSessions = enhancedTokenStore.getActiveSessions(username);

        
        TokenStatistics statistics = getTokenStatistics(username);

        
        List<SecurityEvent> recentEvents = getRecentSecurityEvents(username, 10);

        
        List<EnhancedRefreshTokenStore.TokenUsageHistory> usageHistory = enhancedTokenStore.getTokenHistory(username, 20);

        return new UserTokenDashboard(
                username,
                activeSessions,
                statistics,
                recentEvents,
                usageHistory,
                Instant.now()
        );
    }

    
    public void terminateSession(String username, String deviceId, String reason) {
        log.info("Terminating session for user: {}, device: {}, reason: {}",
                username, deviceId, reason);

        
        enhancedTokenStore.revokeDeviceTokens(username, deviceId, reason);

        
        recordAuditLog(username, "SESSION_TERMINATED", Map.of(
                "deviceId", deviceId,
                "reason", reason,
                "terminatedBy", getCurrentUser()
        ));

        
        publishManagementEvent("SESSION_TERMINATED", username, deviceId, reason);
    }

    
    public void terminateAllSessions(String username, String reason) {
        log.info("Terminating all sessions for user: {}, reason: {}", username, reason);

        
        enhancedTokenStore.revokeAllUserTokens(username, reason);

        
        recordAuditLog(username, "ALL_SESSIONS_TERMINATED", Map.of(
                "reason", reason,
                "terminatedBy", getCurrentUser()
        ));

        
        publishManagementEvent("ALL_SESSIONS_TERMINATED", username, null, reason);
    }

    
    private TokenStatistics getTokenStatistics(String username) {
        String statsKey = STATS_KEY_PREFIX + username;
        Map<Object, Object> stats = redisTemplate.opsForHash().entries(statsKey);

        return new TokenStatistics(
                getLongValue(stats, "totalTokensIssued"),
                getLongValue(stats, "totalTokensRefreshed"),
                getLongValue(stats, "totalTokensRevoked"),
                getLongValue(stats, "suspiciousActivities"),
                getInstant(stats, "lastActivity"),
                getAverageSessionDuration(username)
        );
    }

    
    private Duration getAverageSessionDuration(String username) {
        String pattern = SESSION_KEY_PREFIX + username + ":*:duration";
        Set<String> durationKeys = redisTemplate.keys(pattern);

        if (durationKeys == null || durationKeys.isEmpty()) {
            return Duration.ZERO;
        }

        List<Long> durations = durationKeys.stream()
                .map(key -> redisTemplate.opsForValue().get(key))
                .filter(Objects::nonNull)
                .map(Long::valueOf)
                .collect(Collectors.toList());

        if (durations.isEmpty()) {
            return Duration.ZERO;
        }

        long averageMillis = (long) durations.stream()
                .mapToLong(Long::longValue)
                .average()
                .orElse(0);

        return Duration.ofMillis(averageMillis);
    }

    
    private List<SecurityEvent> getRecentSecurityEvents(String username, int limit) {
        String auditKey = AUDIT_LOG_PREFIX + username;
        List<String> events = redisTemplate.opsForList().range(auditKey, 0, limit - 1);

        if (events == null) {
            return Collections.emptyList();
        }

        return events.stream()
                .map(this::parseSecurityEvent)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    
    private SecurityEvent parseSecurityEvent(String eventJson) {
        try {
            return objectMapper.readValue(eventJson, SecurityEvent.class);
        } catch (JsonProcessingException e) {
            log.error("Failed to parse security event: {}", eventJson, e);
            return null;
        }
    }

    
    private void recordAuditLog(String username, String action, Map<String, Object> details) {
        String auditKey = AUDIT_LOG_PREFIX + username;

        Map<String, Object> auditEntry = new HashMap<>();
        auditEntry.put("action", action);
        auditEntry.put("timestamp", Instant.now().toString());
        auditEntry.put("details", details);

        
        String auditJson = serializeToJson(auditEntry);
        redisTemplate.opsForList().leftPush(auditKey, auditJson);

        
        redisTemplate.opsForList().trim(auditKey, 0, 999);
        redisTemplate.expire(auditKey, 90, TimeUnit.DAYS);
    }

    
    private void publishManagementEvent(String eventType, String username,
                                        String deviceId, String reason) {
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("username", username);
        eventData.put("deviceId", deviceId);
        eventData.put("reason", reason);
        eventData.put("managedBy", getCurrentUser());

        eventPublisher.publishSecurityEvent(eventType, username, "management", eventData);
    }

    

    public void cleanupExpiredTokens() {
        log.info("Starting token cleanup job");

        long startTime = System.currentTimeMillis();
        int cleanedCount = 0;

        try {
            
            

            log.info("Token cleanup completed. Cleaned {} tokens in {} ms",
                    cleanedCount, System.currentTimeMillis() - startTime);

        } catch (Exception e) {
            log.error("Token cleanup job failed", e);
        }
    }

    
    public void updateTokenStatistics(String username, String action) {
        String statsKey = STATS_KEY_PREFIX + username;

        switch (action) {
            case "ISSUED" -> redisTemplate.opsForHash().increment(statsKey, "totalTokensIssued", 1);
            case "REFRESHED" -> redisTemplate.opsForHash().increment(statsKey, "totalTokensRefreshed", 1);
            case "REVOKED" -> redisTemplate.opsForHash().increment(statsKey, "totalTokensRevoked", 1);
            case "SUSPICIOUS" -> redisTemplate.opsForHash().increment(statsKey, "suspiciousActivities", 1);
        }

        redisTemplate.opsForHash().put(statsKey, "lastActivity", Instant.now().toString());
        redisTemplate.expire(statsKey, 90, TimeUnit.DAYS);
    }

    
    public SystemTokenStatistics getSystemStatistics() {
        
        String systemStatsKey = STATS_KEY_PREFIX + "system";
        Map<Object, Object> stats = redisTemplate.opsForHash().entries(systemStatsKey);

        return new SystemTokenStatistics(
                getLongValue(stats, "totalActiveTokens"),
                getLongValue(stats, "totalBlacklistedTokens"),
                getLongValue(stats, "dailyIssuedTokens"),
                getLongValue(stats, "dailyRefreshedTokens"),
                getLongValue(stats, "dailySecurityEvents"),
                getActiveUserCount(),
                getTopAnomalyTypes()
        );
    }

    

    private String getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() &&
            !"anonymousUser".equals(authentication.getName())) {
            return authentication.getName();
        }
        return "system";
    }

    private Long getLongValue(Map<Object, Object> map, String key) {
        Object value = map.get(key);
        return value != null ? Long.parseLong(value.toString()) : 0L;
    }

    private Instant getInstant(Map<Object, Object> map, String key) {
        Object value = map.get(key);
        return value != null ? Instant.parse(value.toString()) : null;
    }

    private String serializeToJson(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize object to JSON: {}", obj, e);
            return "{}";
        }
    }

    private long getActiveUserCount() {
        try {
            
            Set<String> sessionKeys = redisTemplate.keys(SESSION_KEY_PREFIX + "*");
            return sessionKeys != null ? sessionKeys.size() : 0L;
        } catch (Exception e) {
            log.error("Failed to get active user count", e);
            return 0L;
        }
    }

    private Map<String, Long> getTopAnomalyTypes() {
        try {
            
            Map<String, Long> anomalyTypes = new HashMap<>();
            Set<String> auditKeys = redisTemplate.keys(AUDIT_LOG_PREFIX + "*");

            if (auditKeys != null) {
                for (String key : auditKeys) {
                    List<String> logs = redisTemplate.opsForList().range(key, 0, -1);
                    if (logs != null) {
                        for (String logEntry : logs) {
                            try {
                                Map<String, Object> logData = objectMapper.readValue(logEntry, Map.class);
                                String action = (String) logData.get("action");
                                if (action != null && action.contains("anomaly")) {
                                    anomalyTypes.merge(action, 1L, Long::sum);
                                }
                            } catch (Exception e) {
                                log.debug("Failed to parse audit log entry: {}", logEntry);
                            }
                        }
                    }
                }
            }

            return anomalyTypes.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    Map.Entry::getValue,
                    (e1, e2) -> e1,
                    LinkedHashMap::new
                ));
        } catch (Exception e) {
            log.error("Failed to get top anomaly types", e);
            return new HashMap<>();
        }
    }

    

    public record UserTokenDashboard(
            String username,
            List<EnhancedRefreshTokenStore.ActiveSession> activeSessions,
            TokenStatistics statistics,
            List<SecurityEvent> recentSecurityEvents,
            List<EnhancedRefreshTokenStore.TokenUsageHistory> usageHistory,
            Instant generatedAt
    ) {}

    public record TokenStatistics(
            long totalTokensIssued,
            long totalTokensRefreshed,
            long totalTokensRevoked,
            long suspiciousActivities,
            Instant lastActivity,
            Duration averageSessionDuration
    ) {}

    public record SecurityEvent(
            String eventType,
            Instant timestamp,
            String ipAddress,
            String deviceId,
            Map<String, Object> details
    ) {}

    public record SystemTokenStatistics(
            long totalActiveTokens,
            long totalBlacklistedTokens,
            long dailyIssuedTokens,
            long dailyRefreshedTokens,
            long dailySecurityEvents,
            long activeUsers,
            Map<String, Long> topAnomalyTypes
    ) {}
}