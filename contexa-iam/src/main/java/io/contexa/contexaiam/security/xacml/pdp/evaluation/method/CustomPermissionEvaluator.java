package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final ApplicationContext applicationContext;

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permissionAction) {
        if (authentication == null || !authentication.isAuthenticated()) {
                        return false;
        }

        String username = ((UserDto)authentication.getPrincipal()).getUsername();
        String action = permissionAction.toString().toUpperCase();

        try {
            
            Set<String> userPermissions = getUserPermissions(username);

            String requiredPermission = buildPermissionName(targetType, action);

            if (!userPermissions.contains(requiredPermission)) {
                                return false;
            }

                        return true;
            
        } catch (Exception e) {
            log.error("권한 평가 중 오류 발생", e);
            return false;
        }
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {

        return checkBasicPermission(authentication, targetDomainObject, permission.toString());
    }

    private boolean checkBasicPermission(Authentication authentication, Object targetDomainObject, String permissionStr) {
        Serializable id = extractObjectId(targetDomainObject);

        if (permissionStr.contains("_")) {
            String[] parts = permissionStr.split("_", 2);
            String type = parts[0];
            String action = parts[1];
            
                        return hasPermission(authentication, id, type, action);
        } else {
            
            String type = targetDomainObject.getClass().getSimpleName().toUpperCase();
                        return hasPermission(authentication, id, type, permissionStr);
        }
    }

    public boolean checkOwnership(Authentication authentication, Object targetDomainObject, String ownerField) {
        if (authentication == null || !authentication.isAuthenticated()) {
                        return false;
        }
        
        if (targetDomainObject == null || ownerField == null || ownerField.trim().isEmpty()) {
                        return true; 
        }
        
        try {
            String username = authentication.getName();
            Long currentUserId = getCurrentUserId(username);
            if (currentUserId == null) {
                                return false;
            }
            
            Long ownerUserId = getOwnerIdFromObject(targetDomainObject, ownerField);
            if (ownerUserId == null) {
                                return true; 
            }
            
            boolean isOwner = currentUserId.equals(ownerUserId);
                        
            return isOwner;
            
        } catch (Exception e) {
            log.error("소유자 확인 중 오류 발생", e);
            return false;
        }
    }

    private Long getOwnerIdFromObject(Object object, String ownerField) {
        try {
            
            Field field = findField(object.getClass(), ownerField);
            if (field != null) {
                field.setAccessible(true);
                Object value = field.get(object);
                return convertToLong(value);
            }

            String getterName = "get" + ownerField.substring(0, 1).toUpperCase() + ownerField.substring(1);
            Method getter = object.getClass().getMethod(getterName);
            Object value = getter.invoke(object);
            return convertToLong(value);
            
        } catch (Exception e) {
            log.warn("소유자 필드 접근 실패: 필드={}, 객체={}", ownerField, object.getClass().getSimpleName(), e);
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

    private Long convertToLong(Object value) {
        if (value == null) return null;
        if (value instanceof Long) return (Long) value;
        if (value instanceof Integer) return ((Integer) value).longValue();
        if (value instanceof String) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private Long getCurrentUserId(String username) {
        try {
            Optional<Users> userOpt = userRepository.findByUsernameWithGroupsRolesAndPermissions(username);
            return userOpt.map(Users::getId).orElse(null);
        } catch (Exception e) {
            log.error("사용자 ID 조회 실패: {}", username, e);
            return null;
        }
    }

    private Set<String> getUserPermissions(String username) {
        try {
            Optional<Users> userOpt = userRepository.findByUsernameWithGroupsRolesAndPermissions(username);
            if (userOpt.isEmpty()) {
                                return Set.of();
            }
            
            Users user = userOpt.get();
            Set<String> permissions = new HashSet<>(user.getPermissionNames());
            
                        return permissions;
            
        } catch (Exception e) {
            log.error("사용자 권한 조회 실패: {}", username, e);
            return Set.of();
        }
    }

    private String buildPermissionName(String targetType, String action) {
        return String.format("%s_%s", targetType.toUpperCase(), action.toUpperCase());
    }

    private Serializable extractObjectId(Object domainObject) {
        try {
            Method getIdMethod = domainObject.getClass().getMethod("getId");
            Object id = getIdMethod.invoke(domainObject);
            return (Serializable) id;
        } catch (Exception e) {
            log.warn("ID 추출 실패: {}", e.getMessage());
            return null;
        }
    }

    public boolean isOwner(Authentication authentication, Object targetObject, String ownerField) {
        return checkOwnership(authentication, targetObject, ownerField);
    }
}