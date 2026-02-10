package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.concurrent.TimeUnit;

@Slf4j
public class CustomMethodSecurityExpressionRoot extends AbstractAISecurityExpressionRoot implements MethodSecurityExpressionOperations {

    private static final Cache<String, String> actionLocalCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(5, TimeUnit.SECONDS)
            .build();

    private Object filterObject;
    private Object returnObject;
    private Object target;
    private String ownerField;
    private PermissionEvaluator permissionEvaluatorRef;

    public CustomMethodSecurityExpressionRoot(Authentication authentication,
                                              AuthorizationContext authorizationContext,
                                              AuditLogRepository auditLogRepository,
                                              StringRedisTemplate stringRedisTemplate) {
        super(authentication, authorizationContext, auditLogRepository, stringRedisTemplate);
    }

    @Override
    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        super.setPermissionEvaluator(permissionEvaluator);
        this.permissionEvaluatorRef = permissionEvaluator;
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

    @Override
    public boolean hasPermission(Object target, Object permission) {

        if (!super.hasPermission(target, permission)) {
            return false;
        }

        if (StringUtils.hasText(ownerField) && target != null) {
            return checkOwnership(target);
        }
        return true;
    }

    @Override
    public boolean hasPermission(Object targetId, String targetType, Object permission) {

        if (!super.hasPermission(targetId, targetType, permission)) {
            return false;
        }

        if (StringUtils.hasText(ownerField) && targetId != null) {
            return checkOwnershipById((Serializable) targetId, targetType);
        }
        return true;
    }

    private boolean checkOwnership(Object target) {
        try {
            String currentUsername = getAuthentication().getName();

            Field field = target.getClass().getDeclaredField(ownerField);
            field.setAccessible(true);
            Object ownerValue = field.get(target);

            if (ownerValue == null) {
                return false;
            }

            boolean isOwner = currentUsername.equals(ownerValue.toString());
            if (!isOwner) {
                log.error("Ownership verification failed - user: {}, owner: {}", currentUsername, ownerValue);
            }

            return isOwner;
        } catch (Exception e) {
            log.error("Object-based ownership check error: {}", e.getMessage());
            return false;
        }
    }

    private boolean checkOwnershipById(Serializable targetId, String targetType) {
        try {
            PermissionEvaluator evaluator = this.permissionEvaluatorRef;
            if (evaluator instanceof CompositePermissionEvaluator composite) {
                Object entity = composite.resolveEntity(targetId, targetType);
                return entity != null && checkOwnership(entity);
            }
            return false;
        } catch (Exception e) {
            log.error("ID-based ownership check error: {}", e.getMessage());
            return false;
        }
    }

    private String getActionFromLocalCache(String key) {
        return actionLocalCache.getIfPresent(key);
    }

    private void putActionToLocalCache(String key, String action) {
        actionLocalCache.put(key, action);
    }

    @Override
    public void setFilterObject(Object filterObject) {
        this.filterObject = filterObject;
    }

    @Override
    public Object getFilterObject() {
        return this.filterObject;
    }

    @Override
    public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
    }

    @Override
    public Object getReturnObject() {
        return this.returnObject;
    }

    void setThis(Object target) {
        this.target = target;
    }

    public void setOwnerField(String ownerField) {
        this.ownerField = ownerField;
    }

    @Override
    public Object getThis() {
        return this.target;
    }

}
