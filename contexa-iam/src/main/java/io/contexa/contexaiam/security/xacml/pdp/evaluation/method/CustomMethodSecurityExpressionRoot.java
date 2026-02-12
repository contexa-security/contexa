package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;

@Slf4j
public class CustomMethodSecurityExpressionRoot extends AbstractAISecurityExpressionRoot implements MethodSecurityExpressionOperations {

    private static final Cache<String, ZeroTrustAction> actionLocalCache = Caffeine.newBuilder()
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
                                              ZeroTrustActionRedisRepository actionRedisRepository) {
        super(authentication, authorizationContext, auditLogRepository, actionRedisRepository);
    }

    @Override
    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        super.setPermissionEvaluator(permissionEvaluator);
        this.permissionEvaluatorRef = permissionEvaluator;
    }

    @Override
    protected ZeroTrustAction getCurrentAction() {
        String userId = extractUserId();
        if (userId == null) {
            log.error("getCurrentAction: Unable to extract user ID - returning PENDING_ANALYSIS");
            return ZeroTrustAction.PENDING_ANALYSIS;
        }

        String actionCacheKey = "action:" + userId;
        ZeroTrustAction cachedAction = getActionFromLocalCache(actionCacheKey);
        if (cachedAction != null) {
            return cachedAction;
        }

        ZeroTrustAction action = actionRedisRepository.getCurrentAction(userId);

        if (action != ZeroTrustAction.PENDING_ANALYSIS) {
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
            Authentication auth = getAuthentication();

            if (hasAdminRole(auth)) {
                return true;
            }

            String currentUsername = auth.getName();
            Object ownerValue = getOwnerValue(target);

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

    private boolean hasAdminRole(Authentication auth) {
        return auth.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
    }

    private Object getOwnerValue(Object target) throws Exception {
        Field field = findField(target.getClass(), ownerField);
        if (field != null) {
            field.setAccessible(true);
            return field.get(target);
        }

        String getterName = "get" + ownerField.substring(0, 1).toUpperCase()
                + ownerField.substring(1);
        Method getter = target.getClass().getMethod(getterName);
        return getter.invoke(target);
    }

    private Field findField(Class<?> clazz, String fieldName) {
        Class<?> current = clazz;
        while (current != null) {
            try {
                return current.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                current = current.getSuperclass();
            }
        }
        log.error("Owner field not found: field={}, class={}", fieldName, clazz.getSimpleName());
        return null;
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

    private ZeroTrustAction getActionFromLocalCache(String key) {
        return actionLocalCache.getIfPresent(key);
    }

    private void putActionToLocalCache(String key, ZeroTrustAction action) {
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
