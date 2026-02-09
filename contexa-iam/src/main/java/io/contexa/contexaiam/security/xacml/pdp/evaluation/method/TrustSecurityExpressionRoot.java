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

    private final StringRedisTemplate stringRedisTemplate;
    private static final Cache<String, String> actionLocalCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(1, TimeUnit.SECONDS)
            .build();

    public TrustSecurityExpressionRoot(Authentication authentication,
                                       AuthorizationContext authorizationContext,
                                       AuditLogRepository auditLogRepository,
                                       StringRedisTemplate stringRedisTemplate) {
        super(authentication, authorizationContext, auditLogRepository);
        this.stringRedisTemplate = stringRedisTemplate;
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

    private String getActionFromLocalCache(String key) {
        return actionLocalCache.getIfPresent(key);
    }

    private void putActionToLocalCache(String key, String action) {
        actionLocalCache.put(key, action);
    }
}