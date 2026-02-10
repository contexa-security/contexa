package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacommon.security.authority.PermissionAuthority;
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

        return checkPermission(auth, permission);
    }

    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }

        return checkPermission(auth, permission);
    }

    protected boolean checkPermission(Authentication auth, Object permission) {
        if (permission == null) {
            return true;
        }

        String permStr = permission.toString().toUpperCase();
        String domainPrefix = domain().toUpperCase() + "_";

        String action = permStr.startsWith(domainPrefix)
                ? permStr.substring(domainPrefix.length())
                : permStr;

        String httpMethod = mapToHttpMethod(action);
        String domainUpper = domain().toUpperCase();

        return auth.getAuthorities().stream()
                .filter(PermissionAuthority.class::isInstance)
                .map(PermissionAuthority.class::cast)
                .anyMatch(pa -> matchesAction(pa, action, httpMethod)
                                && containsDomain(pa.getAuthority(), domainUpper));
    }

    private boolean matchesAction(PermissionAuthority pa, String action, String httpMethod) {
        if ("URL".equalsIgnoreCase(pa.getTargetType()) && httpMethod != null) {
            return httpMethod.equalsIgnoreCase(pa.getActionType());
        }
        return pa.getAuthority().toUpperCase().contains(action);
    }

    private boolean containsDomain(String authority, String domain) {
        return authority.toUpperCase().contains(domain);
    }

    private String mapToHttpMethod(String action) {
        return switch (action.toUpperCase()) {
            case "READ", "VIEW", "GET" -> "GET";
            case "CREATE", "WRITE", "POST" -> "POST";
            case "UPDATE", "EDIT", "PUT" -> "PUT";
            case "DELETE", "REMOVE" -> "DELETE";
            default -> null;
        };
    }
}
