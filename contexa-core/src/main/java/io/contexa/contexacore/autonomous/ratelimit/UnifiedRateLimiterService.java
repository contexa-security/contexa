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
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * 통합 Rate Limiter 서비스
 *
 * 기능:
 * - 중앙 집중식 Rate Limit 정책 관리
 * - 사용자별, IP별, 엔드포인트별 Rate Limiting
 * - 동적 임계값 조정
 * - 분산 환경 지원 (Redisson)
 */
@Slf4j
@Service
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
        // Metrics 등록
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
     * IP 기반 Rate Limit 확인
     */
    public boolean checkIpRateLimit(String ipAddress) {
        String key = "ratelimit:ip:" + ipAddress;
        return checkRateLimit(key, ipRateLimit, defaultIntervalSeconds, RateLimitType.IP);
    }

    /**
     * 사용자 기반 Rate Limit 확인
     */
    public boolean checkUserRateLimit(String userId) {
        String key = "ratelimit:user:" + userId;
        return checkRateLimit(key, userRateLimit, defaultIntervalSeconds, RateLimitType.USER);
    }

    /**
     * 인증 시도 Rate Limit 확인
     */
    public boolean checkAuthRateLimit(String identifier) {
        String key = "ratelimit:auth:" + identifier;
        return checkRateLimit(key, authRateLimit, authIntervalSeconds, RateLimitType.AUTH);
    }

    /**
     * API 엔드포인트 Rate Limit 확인
     */
    public boolean checkApiRateLimit(String endpoint) {
        String key = "ratelimit:api:" + endpoint;
        return checkRateLimit(key, apiRateLimit, defaultIntervalSeconds, RateLimitType.API);
    }

    /**
     * 커스텀 Rate Limit 확인
     */
    public boolean checkCustomRateLimit(String key, long rate, long intervalSeconds) {
        return checkRateLimit("ratelimit:custom:" + key, rate, intervalSeconds, RateLimitType.CUSTOM);
    }

    /**
     * 통합 Rate Limit 체크 로직
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
            // Fail-open: 에러 시 허용 (가용성 우선)
            allowedRequests.increment();
            return true;
        }
    }

    /**
     * Rate Limiter 가져오기 (캐시 포함)
     */
    private RRateLimiter getRateLimiter(String key, long rate, long intervalSeconds) {
        return rateLimiterCache.computeIfAbsent(key, k -> {
            RRateLimiter limiter = redissonClient.getRateLimiter(k);

            // Rate 설정 (처음 또는 변경 시)
            if (!limiter.isExists() || needsReconfiguration(limiter, rate, intervalSeconds)) {
                limiter.trySetRate(RateType.OVERALL, rate, intervalSeconds, RateIntervalUnit.SECONDS);
                log.info("Rate limiter configured: key={}, rate={}/{} sec", k, rate, intervalSeconds);
            }

            return limiter;
        });
    }

    /**
     * Rate Limiter 재설정 필요 여부 확인
     */
    private boolean needsReconfiguration(RRateLimiter limiter, long rate, long intervalSeconds) {
        // TODO: 현재 설정과 비교하여 변경 필요 여부 판단
        // Redisson API 제약으로 현재 설정 조회 불가
        return false;
    }

    /**
     * 동적 Rate Limit 조정
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
     * 모든 Rate Limiter 정리
     */
    public void clearAllRateLimiters() {
        rateLimiterCache.clear();
        log.info("All rate limiter cache cleared");
    }

    /**
     * Rate Limit 상태 조회
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
     * Rate Limit 타입
     */
    public enum RateLimitType {
        IP,      // IP 주소 기반
        USER,    // 사용자 기반
        AUTH,    // 인증 시도 기반
        API,     // API 엔드포인트 기반
        CUSTOM   // 커스텀
    }

    /**
     * Rate Limit 상태 모델
     */
    @lombok.Data
    @lombok.Builder
    public static class RateLimitStatus {
        private String key;
        private boolean exists;
        private long availablePermits;
    }
}
