package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.notification.UnifiedNotificationService;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexacommon.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Zero Trust 정책 평가자
 * 
 * Redis에 저장된 threat_score를 실시간으로 조회하여 MFA 정책을 결정합니다.
 * AI 호출 없이 밀리초 단위 응답을 보장합니다.
 * 
 * 핵심 특징:
 * - Redis 기반 threat_score 조회 (5ms 이내)
 * - Caffeine 로컬 캐시 (1초 TTL)
 * - 동적 MFA 레벨 결정
 * - 실시간 위험 평가
 * 
 * @author contexa
 * @since 2.0
 */
@Slf4j
@Component
public class ZeroTrustPolicyEvaluator implements MfaPolicyEvaluator {

    private final RedisTemplate<String, Double> redisTemplate;
    private final UnifiedNotificationService notificationService;
    private final AuditLogRepository auditLogRepository;

    public ZeroTrustPolicyEvaluator(
            @Qualifier("zeroTrustRedisTemplate") RedisTemplate<String, Double> redisTemplate,
            UnifiedNotificationService notificationService,
            AuditLogRepository auditLogRepository) {
        this.redisTemplate = redisTemplate;
        this.notificationService = notificationService;
        this.auditLogRepository = auditLogRepository;
    }
    
    // Caffeine 로컬 캐시 (1초 TTL)
    private static final Cache<String, Double> localCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(1, TimeUnit.SECONDS)
            .recordStats()
            .build();
    
    // Redis 키 프리픽스
    private static final String THREAT_SCORE_PREFIX = "threat_score:";
    private static final String THREAT_DETAIL_PREFIX = "threat_detail:";
    private static final String THREAT_PATTERN_PREFIX = "threat_pattern:";
    
    // MFA 정책 임계값
    @Value("${security.zerotrust.thresholds.skip:0.3}")
    private double skipThreshold;
    
    @Value("${security.zerotrust.thresholds.optional:0.5}")
    private double optionalThreshold;
    
    @Value("${security.zerotrust.thresholds.required:0.7}")
    private double requiredThreshold;
    
    @Value("${security.zerotrust.thresholds.strict:0.9}")
    private double strictThreshold;
    
    // Redis 타임아웃
    @Value("${security.zerotrust.redis.timeout:5}")
    private long redisTimeoutMs;
    
    // 기본 위협 점수
    private static final double DEFAULT_THREAT_SCORE = 0.5;
    
    /**
     * Zero Trust 기반으로 MFA 정책을 평가합니다.
     * Redis에서 threat_score를 조회하여 실시간으로 결정합니다.
     */
    @Override
    public MfaDecision evaluatePolicy(FactorContext context) {
        Assert.notNull(context, "FactorContext cannot be null");
        
        String username = context.getUsername();
        log.debug("Starting Zero Trust policy evaluation for user: {}", username);

        long startTime = System.currentTimeMillis();

        // Redis 에서 위협 점수 조회
        double threatScore = getThreatScore(username);
        
        // 추가 컨텍스트 정보 수집
        Map<String, Object> contextInfo = gatherContextInfo(context);
        
        // MFA 결정
        long evaluationTime = System.currentTimeMillis() - startTime;
        
        if (threatScore < skipThreshold) {
            // SKIP: 매우 낮은 위험 (MFA 생략)
            return MfaDecision.builder()
                .required(false)
                .factorCount(0)
                .type(MfaDecision.DecisionType.NO_MFA_REQUIRED)
                .reason(String.format("Low risk user (threat score: %.2f)", threatScore))
                .metadata(Map.of(
                    "threatScore", threatScore,
                    "trustScore", 1.0 - threatScore,
                    "evaluationTime", evaluationTime,
                    "cacheHit", contextInfo.get("cacheHit"),
                    "source", "ZeroTrust"
                ))
                .build();
                
        } else if (threatScore < optionalThreshold) {
            // OPTIONAL: 낮은 위험 (선택적 MFA)
            return MfaDecision.builder()
                .required(true)
                .factorCount(1)
                .type(MfaDecision.DecisionType.AI_ADAPTIVE_MFA)
                .requiredFactors(List.of(AuthType.PASSKEY))
                .reason(String.format("Optional MFA recommended (threat score: %.2f)", threatScore))
                .metadata(Map.of(
                    "threatScore", threatScore,
                    "trustScore", 1.0 - threatScore,
                    "evaluationTime", evaluationTime,
                    "cacheHit", contextInfo.get("cacheHit"),
                    "mfaLevel", "OPTIONAL",
                    "optional", true,
                    "source", "ZeroTrust"
                ))
                .build();
                
        } else if (threatScore < requiredThreshold) {
            // REQUIRED: 중간 위험 (필수 MFA)
            return MfaDecision.builder()
                .required(true)
                .factorCount(2)
                .type(MfaDecision.DecisionType.AI_ADAPTIVE_MFA)
                .requiredFactors(Arrays.asList(AuthType.PASSKEY, AuthType.OTT))
                .reason(String.format("MFA required due to moderate risk (threat score: %.2f)", threatScore))
                .metadata(Map.of(
                    "threatScore", threatScore,
                    "trustScore", 1.0 - threatScore,
                    "evaluationTime", evaluationTime,
                    "cacheHit", contextInfo.get("cacheHit"),
                    "mfaLevel", "REQUIRED",
                    "source", "ZeroTrust"
                ))
                .build();
                
        } else if (threatScore < strictThreshold) {
            // STRICT: 높은 위험 (강화된 MFA)
            return MfaDecision.builder()
                .required(true)
                .factorCount(3)
                .type(MfaDecision.DecisionType.STRONG_MFA)
                .requiredFactors(Arrays.asList(AuthType.PASSKEY, AuthType.OTT, AuthType.MFA))
                .reason(String.format("Strong MFA required due to high risk (threat score: %.2f)", threatScore))
                .metadata(Map.of(
                    "threatScore", threatScore,
                    "trustScore", 1.0 - threatScore,
                    "evaluationTime", evaluationTime,
                    "cacheHit", contextInfo.get("cacheHit"),
                    "mfaLevel", "STRICT",
                    "additionalVerification", true,
                    "source", "ZeroTrust"
                ))
                .build();
                
        } else {
            // BLOCK: 매우 높은 위험 (차단)
            return MfaDecision.builder()
                .required(false)
                .factorCount(0)
                .type(MfaDecision.DecisionType.BLOCKED)
                .reason(String.format("Authentication blocked due to critical risk (threat score: %.2f)", threatScore))
                .metadata(Map.of(
                    "threatScore", threatScore,
                    "trustScore", 1.0 - threatScore,
                    "evaluationTime", evaluationTime,
                    "cacheHit", contextInfo.get("cacheHit"),
                    "blocked", true,
                    "blockReason", "Critical threat level detected",
                    "source", "ZeroTrust"
                ))
                .build();
        }
    }
    
    /**
     * Redis에서 위협 점수를 조회합니다.
     * 로컬 캐시를 먼저 확인하고, 없으면 Redis에서 조회합니다.
     * 
     * @param username 사용자명
     * @return 위협 점수 (0.0 ~ 1.0)
     */
    private double getThreatScore(String username) {
        String cacheKey = THREAT_SCORE_PREFIX + username;
        
        // 1. 로컬 캐시 확인
        Double cachedScore = localCache.getIfPresent(cacheKey);
        if (cachedScore != null) {
            log.trace("Local cache hit for user: {}, score: {}", username, cachedScore);
            return cachedScore;
        }
        
        // 2. Redis 조회
        try {
            Double redisScore = redisTemplate.opsForValue().get(cacheKey);
            
            if (redisScore != null) {
                log.debug("Redis lookup successful for user: {}, score: {}", username, redisScore);
                localCache.put(cacheKey, redisScore);
                return redisScore;
            } else {
                // 새로운 사용자는 위협 점수 0
                log.debug("No threat score found for user: {}, using default: 0.0", username);
                double defaultScore = 0.0;
                localCache.put(cacheKey, defaultScore);
                return defaultScore;
            }
            
        } catch (Exception e) {
            log.error("Redis lookup failed for user: {}, using conservative default: {}", 
                     username, DEFAULT_THREAT_SCORE, e);
            return DEFAULT_THREAT_SCORE;
        }
    }
    
    /**
     * 추가 컨텍스트 정보를 수집합니다.
     */
    private Map<String, Object> gatherContextInfo(FactorContext context) {
        Map<String, Object> info = new HashMap<>();
        
        // 캐시 히트 여부
        String cacheKey = THREAT_SCORE_PREFIX + context.getUsername();
        boolean cacheHit = localCache.getIfPresent(cacheKey) != null;
        info.put("cacheHit", cacheHit);
        
        // HTTP 요청 정보
        HttpServletRequest request = getCurrentRequest();
        if (request != null) {
            info.put("ipAddress", extractIpAddress(request));
            info.put("userAgent", request.getHeader("User-Agent"));
        }
        
        // 세션 정보
        info.put("sessionId", context.getMfaSessionId());
        info.put("flowType", context.getFlowTypeName());
        info.put("retryCount", context.getRetryCount());
        
        return info;
    }
    
    /**
     * 리소스별 위협 점수를 조회합니다.
     * 
     * @param username 사용자명
     * @param resourceId 리소스 ID
     * @return 위협 점수
     */
    public double getResourceThreatScore(String username, String resourceId) {
        String resourceKey = THREAT_SCORE_PREFIX + username + ":" + resourceId;
        
        try {
            Double resourceScore = redisTemplate.opsForValue().get(resourceKey);
            if (resourceScore != null) {
                return resourceScore;
            }
        } catch (Exception e) {
            log.error("Failed to get resource threat score for user: {}, resource: {}", 
                     username, resourceId, e);
        }
        
        // 리소스별 점수가 없으면 사용자 전체 점수 사용
        return getThreatScore(username);
    }
    
    /**
     * 현재 HTTP 요청을 가져옵니다.
     */
    private HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attributes = 
            (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }
    
    /**
     * IP 주소를 추출합니다.
     */
    private String extractIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
    
    /**
     * 캐시 통계를 반환합니다.
     */
    public Map<String, Object> getCacheStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("hitCount", localCache.stats().hitCount());
        stats.put("missCount", localCache.stats().missCount());
        stats.put("hitRate", localCache.stats().hitRate());
        stats.put("evictionCount", localCache.stats().evictionCount());
        stats.put("estimatedSize", localCache.estimatedSize());
        return stats;
    }
    
    @Override
    public boolean supports(FactorContext context) {
        // Zero Trust는 Redis가 사용 가능하고 Zero Trust 모드가 활성화된 경우에만 지원
        return isAvailable() && context != null && context.getAttribute("forceAI") == null;
    }
    
    @Override
    public boolean isAvailable() {
        try {
            redisTemplate.getConnectionFactory().getConnection().ping();
            return true;
        } catch (Exception e) {
            log.warn("Redis connection not available", e);
            return false;
        }
    }
    
    @Override
    public String getName() {
        return "ZeroTrustPolicyEvaluator";
    }
    
    @Override
    public int getPriority() {
        return 100; // 최우선 순위
    }

}