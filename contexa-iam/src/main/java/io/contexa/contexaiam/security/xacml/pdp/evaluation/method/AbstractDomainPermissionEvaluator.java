package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.Optional;

@Slf4j
public abstract class AbstractDomainPermissionEvaluator implements DomainPermissionEvaluator {

    protected abstract String domain();

    protected abstract String repositoryBeanName();

    protected abstract ApplicationContext getApplicationContext();

    @Override
    public boolean supportsTargetType(String targetType) {
        return domain().equalsIgnoreCase(targetType);
    }

    @Override
    public boolean supportsPermission(String permission) {
        if (permission == null) {
            return false;
        }
        return permission.toUpperCase().startsWith(domain() + "_");
    }

    @Override
    public Object resolveEntity(Serializable targetId) {
        if (targetId == null) {
            return null;
        }

        ApplicationContext ctx = getApplicationContext();
        String beanName = repositoryBeanName();

        try {
            if (!ctx.containsBean(beanName)) {
                log.error("Repository bean not found: {}", beanName);
                return null;
            }

            Object repository = ctx.getBean(beanName);
            Method findByIdMethod = repository.getClass().getMethod("findById", Object.class);
            Object result = findByIdMethod.invoke(repository, targetId);

            if (result instanceof Optional<?> optional) {
                return optional.orElse(null);
            }
            return result;
        } catch (Exception e) {
            log.error("Entity resolution failed: domain={}, id={}", domain(), targetId, e);
            return null;
        }
    }

    @Override
    public boolean hasPermission(Authentication auth, Object target, Object permission) {
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }

        if (target instanceof Number || target instanceof String) {
            Object entity = resolveEntity((Serializable) target);
            return entity != null;
        }

        return target != null;
    }

    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }

        Object entity = resolveEntity(targetId);
        if (entity == null) {
            log.error("Entity not found: domain={}, id={}", domain(), targetId);
            return false;
        }
        return true;
    }
}
