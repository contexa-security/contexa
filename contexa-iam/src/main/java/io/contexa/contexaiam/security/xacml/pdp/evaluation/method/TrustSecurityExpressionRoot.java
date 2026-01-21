package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Slf4j
public class TrustSecurityExpressionRoot extends AbstractAISecurityExpressionRoot {

    private final RedisTemplate<String, Double> redisTemplate;
    private final StringRedisTemplate stringRedisTemplate;  

    private static final Cache<String, Double> localCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(1, TimeUnit.SECONDS)
            .build();

    private static final String THREAT_SCORE_PREFIX = "threat_score:";
    private static final String THREAT_DETAIL_PREFIX = "threat_detail:";
    private static final String THREAT_PATTERN_PREFIX = "threat_pattern:";

    private static final Duration REDIS_TIMEOUT = Duration.ofMillis(5); 
    
    public TrustSecurityExpressionRoot(Authentication authentication,
                                       AttributeInformationPoint attributePIP,
                                       AICoreOperations aINativeProcessor,
                                       AuthorizationContext authorizationContext,
                                       AuditLogRepository auditLogRepository,
                                       RedisTemplate<String, Double> redisTemplate,
                                       StringRedisTemplate stringRedisTemplate) {
        super(authentication, attributePIP, aINativeProcessor, authorizationContext, auditLogRepository);
        this.redisTemplate = redisTemplate;
        this.stringRedisTemplate = stringRedisTemplate;
            }

    private double getThreatScore(String userId) {
        String cacheKey = THREAT_SCORE_PREFIX + userId;

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

                                return 0.5; 
            }
        } catch (Exception e) {
            log.error("Redis 조회 실패 - userId: {}, 기본값 사용: 0.5", userId, e);
            return 0.5; 
        }
    }

    @Override
    protected String getCurrentActivityDescription() {
        
        if (authorizationContext != null) {
            String action = authorizationContext.action();
            if (authorizationContext.resource() != null) {
                String resourceId = authorizationContext.resource().identifier();
                return String.format("%s %s", action, resourceId);
            }
            return action;
        }
        return "unknown activity";
    }

    public boolean hasResourceAccess(String resourceId, double threshold) {
        String userId = extractUserId();
        if (userId == null || resourceId == null) {
            return false;
        }

        String resourceKey = THREAT_SCORE_PREFIX + userId + ":" + resourceId;
        try {
            Double resourceScore = redisTemplate.opsForValue().get(resourceKey);
            if (resourceScore == null) {
                
                resourceScore = getThreatScore(userId);
            }
            
            boolean hasAccess = resourceScore <= threshold;
                        
            return hasAccess;
        } catch (Exception e) {
            log.error("리소스 접근 평가 실패 - userId: {}, resourceId: {}", userId, resourceId, e);
            return false;
        }
    }

    public boolean hasTemporaryPermission(String permissionType) {
        String userId = extractUserId();
        if (userId == null) {
            return false;
        }
        
        String tempPermKey = "temp_permission:" + userId + ":" + permissionType;
        try {
            Boolean hasPermission = redisTemplate.hasKey(tempPermKey);
                        return Boolean.TRUE.equals(hasPermission);
        } catch (Exception e) {
            log.error("임시 권한 확인 실패 - userId: {}, type: {}", userId, permissionType, e);
            return false;
        }
    }
    
    @Override
    protected ContextExtractionResult extractCurrentContext() {
        
        return extractContextFromAuthorizationContext();
    }

    @Override
    protected String calculateContextHash() {
        
        return calculateContextHashFromAuthorizationContext();
    }

    @Override
    protected String getCurrentAction() {
        String userId = extractUserId();
        if (userId == null) {
            log.warn("getCurrentAction: 사용자 ID를 추출할 수 없음 - PENDING_ANALYSIS 반환");
            return "PENDING_ANALYSIS";
        }

        String actionCacheKey = "action:" + userId;
        String cachedAction = getActionFromLocalCache(actionCacheKey);
        if (cachedAction != null) {
                        return cachedAction;
        }

        String redisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
        String action = getActionFromRedisHash(userId, redisKey, stringRedisTemplate);

        if (!"PENDING_ANALYSIS".equals(action)) {
            putActionToLocalCache(actionCacheKey, action);
        }

        return action;
    }

    private static final Cache<String, String> actionLocalCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(1, TimeUnit.SECONDS)
            .build();

    private String getActionFromLocalCache(String key) {
        return actionLocalCache.getIfPresent(key);
    }

    private void putActionToLocalCache(String key, String action) {
        actionLocalCache.put(key, action);
    }
}