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

/**
 * 리프레시 토큰 관리 서비스
 *
 * 관리자 및 사용자를 위한 토큰 관리 기능 제공:
 * - 활성 세션 조회 및 관리
 * - 토큰 사용 통계
 * - 보안 감사 로그
 * - 자동 정리 작업
 *
 * @since 2024.12
 */
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

    /**
     * 사용자 토큰 대시보드 정보 조회
     */
    public UserTokenDashboard getUserTokenDashboard(String username) {
        // 활성 세션 조회
        List<EnhancedRefreshTokenStore.ActiveSession> activeSessions = enhancedTokenStore.getActiveSessions(username);

        // 토큰 통계 조회
        TokenStatistics statistics = getTokenStatistics(username);

        // 최근 보안 이벤트 조회
        List<SecurityEvent> recentEvents = getRecentSecurityEvents(username, 10);

        // 토큰 사용 이력
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

    /**
     * 특정 세션 종료
     */
    public void terminateSession(String username, String deviceId, String reason) {
        log.info("Terminating session for user: {}, device: {}, reason: {}",
                username, deviceId, reason);

        // 토큰 무효화
        enhancedTokenStore.revokeDeviceTokens(username, deviceId, reason);

        // 감사 로그 기록
        recordAuditLog(username, "SESSION_TERMINATED", Map.of(
                "deviceId", deviceId,
                "reason", reason,
                "terminatedBy", getCurrentUser()
        ));

        // 이벤트 발행
        publishManagementEvent("SESSION_TERMINATED", username, deviceId, reason);
    }

    /**
     * 사용자의 모든 세션 종료
     */
    public void terminateAllSessions(String username, String reason) {
        log.info("Terminating all sessions for user: {}, reason: {}", username, reason);

        // 모든 토큰 무효화
        enhancedTokenStore.revokeAllUserTokens(username, reason);

        // 감사 로그 기록
        recordAuditLog(username, "ALL_SESSIONS_TERMINATED", Map.of(
                "reason", reason,
                "terminatedBy", getCurrentUser()
        ));

        // 이벤트 발행
        publishManagementEvent("ALL_SESSIONS_TERMINATED", username, null, reason);
    }

    /**
     * 토큰 통계 조회
     */
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

    /**
     * 평균 세션 지속 시간 계산
     */
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

    /**
     * 최근 보안 이벤트 조회
     */
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

    /**
     * 보안 이벤트 파싱
     */
    private SecurityEvent parseSecurityEvent(String eventJson) {
        try {
            return objectMapper.readValue(eventJson, SecurityEvent.class);
        } catch (JsonProcessingException e) {
            log.error("Failed to parse security event: {}", eventJson, e);
            return null;
        }
    }

    /**
     * 감사 로그 기록
     */
    private void recordAuditLog(String username, String action, Map<String, Object> details) {
        String auditKey = AUDIT_LOG_PREFIX + username;

        Map<String, Object> auditEntry = new HashMap<>();
        auditEntry.put("action", action);
        auditEntry.put("timestamp", Instant.now().toString());
        auditEntry.put("details", details);

        // JSON으로 직렬화하여 저장
        String auditJson = serializeToJson(auditEntry);
        redisTemplate.opsForList().leftPush(auditKey, auditJson);

        // 최근 1000개만 유지
        redisTemplate.opsForList().trim(auditKey, 0, 999);
        redisTemplate.expire(auditKey, 90, TimeUnit.DAYS);
    }

    /**
     * 관리 이벤트 발행
     */
    private void publishManagementEvent(String eventType, String username,
                                        String deviceId, String reason) {
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("username", username);
        eventData.put("deviceId", deviceId);
        eventData.put("reason", reason);
        eventData.put("managedBy", getCurrentUser());

        eventPublisher.publishSecurityEvent(eventType, username, "management", eventData);
    }

    /**
     * 토큰 정리 작업 (매일 새벽 2시 실행)
     */
//    @Scheduled(cron = "0 0 2 * * *")
    public void cleanupExpiredTokens() {
        log.info("Starting token cleanup job");

        long startTime = System.currentTimeMillis();
        int cleanedCount = 0;

        try {
            // 만료된 토큰 정리 로직
            // 구현 세부사항...

            log.info("Token cleanup completed. Cleaned {} tokens in {} ms",
                    cleanedCount, System.currentTimeMillis() - startTime);

        } catch (Exception e) {
            log.error("Token cleanup job failed", e);
        }
    }

    /**
     * 토큰 사용 통계 업데이트
     */
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

    /**
     * 시스템 전체 토큰 통계
     */
    public SystemTokenStatistics getSystemStatistics() {
        // 전체 시스템 통계 조회
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

    // ===== 유틸리티 메서드 =====

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
            // 활성 세션 키 패턴으로 조회
            Set<String> sessionKeys = redisTemplate.keys(SESSION_KEY_PREFIX + "*");
            return sessionKeys != null ? sessionKeys.size() : 0L;
        } catch (Exception e) {
            log.error("Failed to get active user count", e);
            return 0L;
        }
    }

    private Map<String, Long> getTopAnomalyTypes() {
        try {
            // 감사 로그에서 이상 유형별 카운트 조회
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

    // ===== DTO 클래스 =====

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