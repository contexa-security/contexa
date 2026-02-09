package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;

import java.util.concurrent.TimeUnit;

@Slf4j
public class TrustSecurityExpressionRoot extends AbstractAISecurityExpressionRoot {

    private static final Cache<String, String> actionLocalCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(5, TimeUnit.SECONDS)
            .build();

    public TrustSecurityExpressionRoot(Authentication authentication,
                                       AuthorizationContext authorizationContext,
                                       AuditLogRepository auditLogRepository,
                                       StringRedisTemplate stringRedisTemplate) {
        super(authentication, authorizationContext, auditLogRepository, stringRedisTemplate);
    }

    protected String getCurrentAction() {
        String userId = extractUserId();
        if (userId == null) {
            log.error("getCurrentAction: Unable to extract user ID - returning PENDING_ANALYSIS");
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