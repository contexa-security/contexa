package io.contexa.contexacore.autonomous.ratelimit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RRateLimiter;
import org.redisson.api.RateIntervalUnit;
import org.redisson.api.RateType;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.annotation.Value;


import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * ?�합 Rate Limiter ?�비??
 *
 * 기능:
 * - 중앙 집중??Rate Limit ?�책 관�?
 * - ?�용?�별, IP�? ?�드?�인?�별 Rate Limiting
 * - ?�적 ?�계�?조정
 * - 분산 ?�경 지??(Redisson)
 */
@Slf4j
@RequiredArgsConstructor
public class UnifiedRateLimiterService {

    private final RedissonClient redissonClient;
    private final MeterRegistry meterRegistry;

    @Value("${security.rate-limit.default.requests:100}")
    private long defaultRateLimit;

    @Value("${security.rate-limit.default.interval-seconds:60}")
    private long defaultIntervalSeconds;

    @Value("${security.rate-limit.ip.requests:50}")
    private long ipRateLimit;

    @Value("${security.rate-limit.user.requests:200}")
    private long userRateLimit;

    @Value("${security.rate-limit.api.requests:1000}")
    private long apiRateLimit;

    @Value("${security.rate-limit.auth.requests:10}")
    private long authRateLimit;

    @Value("${security.rate-limit.auth.interval-seconds:60}")
    private long authIntervalSeconds;

    // Rate Limiter 캐시
    private final Map<String, RRateLimiter> rateLimiterCache = new ConcurrentHashMap<>();

    // Metrics
    private Counter allowedRequests;
    private Counter rejectedRequests;

    @PostConstruct
    public void initialize() {
        // Metrics ?�록
        allowedRequests = Counter.builder("ratelimit.requests.allowed")
            .description("Number of allowed requests")
            .register(meterRegistry);

        rejectedRequests = Counter.builder("ratelimit.requests.rejected")
            .description("Number of rejected requests due to rate limit")
            .register(meterRegistry);

        log.info("UnifiedRateLimiterService initialized");
        log.info("  Default: {} req/{} sec", defaultRateLimit, defaultIntervalSeconds);
        log.info("  IP: {} req/60 sec", ipRateLimit);
        log.info("  User: {} req/60 sec", userRateLimit);
        log.info("  API: {} req/60 sec", apiRateLimit);
        log.info("  Auth: {} req/{} sec", authRateLimit, authIntervalSeconds);
    }

    /**
     * IP 기반 Rate Limit ?�인
     */
    public boolean checkIpRateLimit(String ipAddress) {
        String key = "ratelimit:ip:" + ipAddress;
        return checkRateLimit(key, ipRateLimit, defaultIntervalSeconds, RateLimitType.IP);
    }

    /**
     * ?�용??기반 Rate Limit ?�인
     */
    public boolean checkUserRateLimit(String userId) {
        String key = "ratelimit:user:" + userId;
        return checkRateLimit(key, userRateLimit, defaultIntervalSeconds, RateLimitType.USER);
    }

    /**
     * ?�증 ?�도 Rate Limit ?�인
     */
    public boolean checkAuthRateLimit(String identifier) {
        String key = "ratelimit:auth:" + identifier;
        return checkRateLimit(key, authRateLimit, authIntervalSeconds, RateLimitType.AUTH);
    }

    /**
     * API ?�드?�인??Rate Limit ?�인
     */
    public boolean checkApiRateLimit(String endpoint) {
        String key = "ratelimit:api:" + endpoint;
        return checkRateLimit(key, apiRateLimit, defaultIntervalSeconds, RateLimitType.API);
    }

    /**
     * 커스?� Rate Limit ?�인
     */
    public boolean checkCustomRateLimit(String key, long rate, long intervalSeconds) {
        return checkRateLimit("ratelimit:custom:" + key, rate, intervalSeconds, RateLimitType.CUSTOM);
    }

    /**
     * ?�합 Rate Limit 체크 로직
     */
    private boolean checkRateLimit(String key, long rate, long intervalSeconds, RateLimitType type) {
        try {
            RRateLimiter rateLimiter = getRateLimiter(key, rate, intervalSeconds);

            boolean allowed = rateLimiter.tryAcquire(1, 0, TimeUnit.MILLISECONDS);

            if (allowed) {
                allowedRequests.increment();
                log.trace("Rate limit check PASSED: key={}, type={}", key, type);
            } else {
                rejectedRequests.increment();
                log.warn("Rate limit EXCEEDED: key={}, type={}, limit={}/{} sec",
                    key, type, rate, intervalSeconds);
            }

            return allowed;

        } catch (Exception e) {
            log.error("Failed to check rate limit: key={}", key, e);
            // Fail-open: ?�러 ???�용 (가?�성 ?�선)
            allowedRequests.increment();
            return true;
        }
    }

    /**
     * Rate Limiter 가?�오�?(캐시 ?�함)
     */
    private RRateLimiter getRateLimiter(String key, long rate, long intervalSeconds) {
        return rateLimiterCache.computeIfAbsent(key, k -> {
            RRateLimiter limiter = redissonClient.getRateLimiter(k);

            // Rate ?�정 (처음 ?�는 변�???
            if (!limiter.isExists() || needsReconfiguration(limiter, rate, intervalSeconds)) {
                limiter.trySetRate(RateType.OVERALL, rate, intervalSeconds, RateIntervalUnit.SECONDS);
                log.info("Rate limiter configured: key={}, rate={}/{} sec", k, rate, intervalSeconds);
            }

            return limiter;
        });
    }

    /**
     * Rate Limiter ?�설???�요 ?��? ?�인
     */
    private boolean needsReconfiguration(RRateLimiter limiter, long rate, long intervalSeconds) {
        // TODO: ?�재 ?�정�?비교?�여 변�??�요 ?��? ?�단
        // Redisson API ?�약?�로 ?�재 ?�정 조회 불�?
        return false;
    }

    /**
     * ?�적 Rate Limit 조정
     */
    public void adjustRateLimit(String key, long newRate, long intervalSeconds) {
        try {
            RRateLimiter limiter = redissonClient.getRateLimiter(key);
            limiter.trySetRate(RateType.OVERALL, newRate, intervalSeconds, RateIntervalUnit.SECONDS);

            // 캐시 갱신
            rateLimiterCache.put(key, limiter);

            log.info("Rate limit adjusted: key={}, newRate={}/{} sec", key, newRate, intervalSeconds);

        } catch (Exception e) {
            log.error("Failed to adjust rate limit: key={}", key, e);
        }
    }

    /**
     * Rate Limit 리셋
     */
    public void resetRateLimit(String key) {
        try {
            RRateLimiter limiter = redissonClient.getRateLimiter(key);
            limiter.delete();
            rateLimiterCache.remove(key);

            log.info("Rate limit reset: key={}", key);

        } catch (Exception e) {
            log.error("Failed to reset rate limit: key={}", key, e);
        }
    }

    /**
     * 모든 Rate Limiter ?�리
     */
    public void clearAllRateLimiters() {
        rateLimiterCache.clear();
        log.info("All rate limiter cache cleared");
    }

    /**
     * Rate Limit ?�태 조회
     */
    public RateLimitStatus getRateLimitStatus(String key) {
        try {
            RRateLimiter limiter = rateLimiterCache.get(key);
            if (limiter == null) {
                return RateLimitStatus.builder()
                    .key(key)
                    .exists(false)
                    .build();
            }

            long availablePermits = limiter.availablePermits();

            return RateLimitStatus.builder()
                .key(key)
                .exists(true)
                .availablePermits(availablePermits)
                .build();

        } catch (Exception e) {
            log.error("Failed to get rate limit status: key={}", key, e);
            return RateLimitStatus.builder()
                .key(key)
                .exists(false)
                .build();
        }
    }

    /**
     * Rate Limit ?�??
     */
    public enum RateLimitType {
        IP,      // IP 주소 기반
        USER,    // ?�용??기반
        AUTH,    // ?�증 ?�도 기반
        API,     // API ?�드?�인??기반
        CUSTOM   // 커스?�
    }

    /**
     * Rate Limit ?�태 모델
     */
    @lombok.Data
    @lombok.Builder
    public static class RateLimitStatus {
        private String key;
        private boolean exists;
        private long availablePermits;
    }
}
