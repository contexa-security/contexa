package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final UserRepository userRepository;
    private final ApplicationContext applicationContext;

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId,
                                 String targetType, Object permissionAction) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        Object targetDomainObject = resolveEntity(targetId, targetType);
        if (targetDomainObject == null) {
            log.error("Entity not found: type={}, id={}", targetType, targetId);
            return false;
        }

        return hasPermission(authentication, targetDomainObject, permissionAction);
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject,
                                 Object permission) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        return targetDomainObject != null;
    }

    public boolean checkOwnership(Authentication authentication, Object targetDomainObject,
                                  String ownerField) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        if (targetDomainObject == null || ownerField == null || ownerField.trim().isEmpty()) {
            return true;
        }

        try {
            String username = authentication.getName();
            String currentUserName = getCurrentUserName(username);
            if (currentUserName == null) {
                return false;
            }

            String ownerUserId = getOwnerIdFromObject(targetDomainObject, ownerField);
            if (ownerUserId == null) {
                return true;
            }

            return currentUserName.equals(ownerUserId);

        } catch (Exception e) {
            log.error("Ownership verification failed", e);
            return false;
        }
    }

    public boolean isOwner(Authentication authentication, Object targetObject, String ownerField) {
        return checkOwnership(authentication, targetObject, ownerField);
    }

    private Object resolveEntity(Serializable targetId, String targetType) {
        if (targetId == null || targetType == null || applicationContext == null) {
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
            log.error("Entity resolution failed: type={}, id={}", targetType, targetId, e);
            return null;
        }
    }

    private String getOwnerIdFromObject(Object object, String ownerField) {
        try {
            Field field = findField(object.getClass(), ownerField);
            if (field != null) {
                field.setAccessible(true);
                Object value = field.get(object);
                return String.valueOf(value);
            }

            String getterName = "get" + ownerField.substring(0, 1).toUpperCase()
                    + ownerField.substring(1);
            Method getter = object.getClass().getMethod(getterName);
            Object value = getter.invoke(object);
            return String.valueOf(value);

        } catch (Exception e) {
            log.error("Owner field access failed: field={}, object={}",
                    ownerField, object.getClass().getSimpleName(), e);
            return null;
        }
    }

    private Field findField(Class<?> clazz, String fieldName) {
        Class<?> currentClass = clazz;
        while (currentClass != null) {
            try {
                return currentClass.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                currentClass = currentClass.getSuperclass();
            }
        }
        return null;
    }

    private String getCurrentUserName(String username) {
        try {
            Optional<Users> userOpt = userRepository.findByUsernameWithGroupsRolesAndPermissions(username);
            return userOpt.map(Users::getUsername).orElse(null);
        } catch (Exception e) {
            log.error("User lookup failed: {}", username, e);
            return null;
        }
    }
}
