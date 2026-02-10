package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.Optional;
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
    private ApplicationContext applicationContext;

    public CustomMethodSecurityExpressionRoot(Authentication authentication,
                                              AuthorizationContext authorizationContext,
                                              AuditLogRepository auditLogRepository,
                                              StringRedisTemplate stringRedisTemplate) {
        super(authentication, authorizationContext, auditLogRepository, stringRedisTemplate);
    }

    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
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
        // Step 1: Delegate to PermissionEvaluator via super (entity existence check)
        if (!super.hasPermission(targetId, targetType, permission)) {
            return false;
        }

        // Step 2: Action-based ownership policy
        if (StringUtils.hasText(ownerField) && targetId != null) {
            String action = permission != null ? permission.toString().toUpperCase() : "";

            // READ/VIEW/GET actions do not require ownership
            if (isReadAction(action)) {
                return true;
            }

            // WRITE/UPDATE/DELETE actions require ownership
            return checkOwnershipById((Serializable) targetId, targetType);
        }

        return true;
    }

    private boolean isReadAction(String action) {
        return "READ".equals(action) || "VIEW".equals(action) || "GET".equals(action);
    }

    private boolean checkOwnership(Object target) {
        try {
            String currentUsername = getAuthentication().getName();

            java.lang.reflect.Field field = target.getClass().getDeclaredField(ownerField);
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
            Object entity = findEntityById(targetId, targetType);
            if (entity == null) {
                return false;
            }
            return checkOwnership(entity);

        } catch (Exception e) {
            log.error("ID-based ownership check error: {}", e.getMessage());
            return false;
        }
    }

    private Object findEntityById(Serializable targetId, String targetType) {
        if (applicationContext == null || targetType == null) {
            return null;
        }

        try {
            String repositoryBeanName = targetType.toLowerCase() + "Repository";

            if (!applicationContext.containsBean(repositoryBeanName)) {
                log.error("Repository bean not found: {}", repositoryBeanName);
                return null;
            }

            Object repository = applicationContext.getBean(repositoryBeanName);
            Method findByIdMethod = repository.getClass().getMethod("findById", Object.class);
            Object result = findByIdMethod.invoke(repository, targetId);

            if (result instanceof Optional<?> optional) {
                return optional.orElse(null);
            }
            return result;
        } catch (Exception e) {
            log.error("Entity lookup failed: targetId={}, targetType={}", targetId, targetType, e);
            return null;
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
