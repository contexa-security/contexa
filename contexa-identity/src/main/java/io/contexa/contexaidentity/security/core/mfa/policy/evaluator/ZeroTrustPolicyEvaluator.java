package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.notification.NotificationService;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
public class ZeroTrustPolicyEvaluator implements MfaPolicyEvaluator {

    private final RedisTemplate<String, Double> redisTemplate;
    private final NotificationService notificationService; 
    private final AuditLogRepository auditLogRepository;

    public ZeroTrustPolicyEvaluator(
            @Qualifier("trustScoreRedisTemplate") RedisTemplate<String, Double> redisTemplate,
            @Autowired(required = false) NotificationService notificationService,
            AuditLogRepository auditLogRepository) {
        this.redisTemplate = redisTemplate;
        this.notificationService = notificationService;
        this.auditLogRepository = auditLogRepository;
    }

    private static final Cache<String, Double> localCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(1, TimeUnit.SECONDS)
            .recordStats()
            .build();

    private static final String THREAT_SCORE_PREFIX = "threat_score:";
    private static final String THREAT_DETAIL_PREFIX = "threat_detail:";
    private static final String THREAT_PATTERN_PREFIX = "threat_pattern:";

    @Value("${security.zerotrust.thresholds.skip:0.3}")
    private double skipThreshold;
    
    @Value("${security.zerotrust.thresholds.optional:0.5}")
    private double optionalThreshold;
    
    @Value("${security.zerotrust.thresholds.required:0.7}")
    private double requiredThreshold;
    
    @Value("${security.zerotrust.thresholds.strict:0.9}")
    private double strictThreshold;

    @Value("${security.zerotrust.redis.timeout:5}")
    private long redisTimeoutMs;

    private static final double DEFAULT_THREAT_SCORE = 0.5;

    @Override
    public MfaDecision evaluatePolicy(FactorContext context) {
        Assert.notNull(context, "FactorContext cannot be null");
        
        String username = context.getUsername();
        
        long startTime = System.currentTimeMillis();

        double threatScore = getThreatScore(username);

        Map<String, Object> contextInfo = gatherContextInfo(context);

        long evaluationTime = System.currentTimeMillis() - startTime;
        
        if (threatScore < skipThreshold) {
            
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

    private double getThreatScore(String username) {
        String cacheKey = THREAT_SCORE_PREFIX + username;

        Double cachedScore = localCache.getIfPresent(cacheKey);
        if (cachedScore != null) {
                        return cachedScore;
        }

        try {
            Double redisScore = redisTemplate.opsForValue().get(cacheKey);
            
            if (redisScore != null) {
                                localCache.put(cacheKey, redisScore);
                return redisScore;
            } else {
                
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

    private Map<String, Object> gatherContextInfo(FactorContext context) {
        Map<String, Object> info = new HashMap<>();

        String cacheKey = THREAT_SCORE_PREFIX + context.getUsername();
        boolean cacheHit = localCache.getIfPresent(cacheKey) != null;
        info.put("cacheHit", cacheHit);

        HttpServletRequest request = getCurrentRequest();
        if (request != null) {
            info.put("ipAddress", extractIpAddress(request));
            info.put("userAgent", request.getHeader("User-Agent"));
        }

        info.put("sessionId", context.getMfaSessionId());
        info.put("flowType", context.getFlowTypeName());
        info.put("retryCount", context.getRetryCount());
        
        return info;
    }

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

        return getThreatScore(username);
    }

    private HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attributes = 
            (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }

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
        return 100; 
    }

}