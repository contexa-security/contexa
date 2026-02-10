package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

@Slf4j
public class CompositePermissionEvaluator implements PermissionEvaluator {

    private final List<DomainPermissionEvaluator> evaluators;
    private final UserRepository userRepository;

    public CompositePermissionEvaluator(List<DomainPermissionEvaluator> evaluators,
                                        UserRepository userRepository) {
        this.evaluators = evaluators.stream()
                .sorted(Comparator.comparingInt(
                        (DomainPermissionEvaluator e) -> ((AbstractDomainPermissionEvaluator) e).domain().length()
                ).reversed())
                .toList();
        this.userRepository = userRepository;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject,
                                 Object permission) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        if (permission != null) {
            String permStr = permission.toString();
            for (DomainPermissionEvaluator evaluator : evaluators) {
                if (evaluator.supportsPermission(permStr)) {
                    return evaluator.hasPermission(authentication, targetDomainObject, permission);
                }
            }
        }

        return targetDomainObject != null;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId,
                                 String targetType, Object permissionAction) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        for (DomainPermissionEvaluator evaluator : evaluators) {
            if (evaluator.supportsTargetType(targetType)) {
                return evaluator.hasPermission(authentication, targetId, targetType, permissionAction);
            }
        }

        throw new IllegalArgumentException("No DomainPermissionEvaluator found for targetType: " + targetType);
    }

    public Object resolveEntity(Serializable targetId, String targetType) {
        for (DomainPermissionEvaluator evaluator : evaluators) {
            if (evaluator.supportsTargetType(targetType)) {
                return evaluator.resolveEntity(targetId);
            }
        }
        throw new IllegalArgumentException("No DomainPermissionEvaluator found for targetType: " + targetType);
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
