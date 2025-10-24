package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexaiam.domain.dto.UserDto;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * DB 기반 권한 평가기 - Spring Security 표준 방식
 * 
 * 핵심 원칙:
 * 1. hasPermission 메서드에서 모든 권한 검증 처리
 * 2. @Protectable 애노테이션 기반 자동 소유자 확인  
 * 3. Spring Security 표준 패턴 준수
 * 4. 단일 진입점으로 간단하고 명확한 구조
 */
@Component("customPermissionEvaluator")
@Slf4j
@RequiredArgsConstructor
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final ApplicationContext applicationContext;

    /**
     * 핵심 권한 평가 메서드 - ID 기반
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permissionAction) {
        if (authentication == null || !authentication.isAuthenticated()) {
            log.debug("인증되지 않은 사용자");
            return false;
        }

        String username = ((UserDto)authentication.getPrincipal()).getUsername();
        String action = permissionAction.toString().toUpperCase();
        
        log.debug("권한 평가: 사용자={}, 대상={}#{}, 액션={}", username, targetType, targetId, action);

        try {
            // 1️⃣ 사용자의 모든 권한 조회 (역할 기반)
            Set<String> userPermissions = getUserPermissions(username);
            
            // 2️⃣ 요청된 권한명 생성
            String requiredPermission = buildPermissionName(targetType, action);
            
            // 3️⃣ 권한 보유 여부 확인
            if (!userPermissions.contains(requiredPermission)) {
                log.debug("권한 부족: {} 권한 없음", requiredPermission);
                return false;
            }
            

            log.debug("권한 승인: {}는 {}#{} 에 대한 {} 권한 보유", username, targetType, targetId, action);
            return true;
            
        } catch (Exception e) {
            log.error("권한 평가 중 오류 발생", e);
            return false;
        }
    }

    /**
     * 핵심 권한 평가 메서드 - 도메인 객체 기반 (Spring Security 표준)
     * 
     * CustomMethodSecurityExpressionRoot에서 이미 hasPermission 오버라이드하여 소유자 확인 처리하므로
     * 여기서는 기본 권한 확인만 수행 (중복 제거)
     */
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        log.debug("객체 기반 권한 확인 시작: 사용자={}, 대상={}, 권한={}",
                ((UserDto)authentication.getPrincipal()).getUsername(),
                 targetDomainObject.getClass().getSimpleName(), 
                 permission);
        
        // 기본 권한 확인만 수행 (소유자 확인은 CustomMethodSecurityExpressionRoot에서 처리됨)
        return checkBasicPermission(authentication, targetDomainObject, permission.toString());
    }
    
    /**
     * 기본 권한 확인
     */
    private boolean checkBasicPermission(Authentication authentication, Object targetDomainObject, String permissionStr) {
        Serializable id = extractObjectId(targetDomainObject);
        
        // 타입_액션 형태인지 확인 (예: GROUP_UPDATE, USER_CREATE)
        if (permissionStr.contains("_")) {
            String[] parts = permissionStr.split("_", 2);
            String type = parts[0];
            String action = parts[1];
            
            log.debug("타입_액션 파싱: {} → 타입={}, 액션={}", permissionStr, type, action);
            return hasPermission(authentication, id, type, action);
        } else {
            // 기존 방식: 클래스명에서 타입 추출
            String type = targetDomainObject.getClass().getSimpleName().toUpperCase();
            log.debug("클래스명 타입 추출: {} → 타입={}", targetDomainObject.getClass().getSimpleName(), type);
            return hasPermission(authentication, id, type, permissionStr);
        }
    }
    
    /**
     * 🏠 ownerField 기반 동적 소유자 확인
     */
    public boolean checkOwnership(Authentication authentication, Object targetDomainObject, String ownerField) {
        if (authentication == null || !authentication.isAuthenticated()) {
            log.debug("인증되지 않은 사용자 - 소유자 확인 실패");
            return false;
        }
        
        if (targetDomainObject == null || ownerField == null || ownerField.trim().isEmpty()) {
            log.debug("소유자 확인 생략: 대상 객체 또는 ownerField 없음");
            return true; // 소유자 확인을 하지 않으면 통과
        }
        
        try {
            String username = authentication.getName();
            Long currentUserId = getCurrentUserId(username);
            if (currentUserId == null) {
                log.debug("현재 사용자 ID 조회 실패: {}", username);
                return false;
            }
            
            Long ownerUserId = getOwnerIdFromObject(targetDomainObject, ownerField);
            if (ownerUserId == null) {
                log.debug("소유자 ID 추출 실패: 객체={}, 필드={}", targetDomainObject.getClass().getSimpleName(), ownerField);
                return true; // 소유자 정보가 없으면 통과
            }
            
            boolean isOwner = currentUserId.equals(ownerUserId);
            log.debug("소유자 확인: 사용자={}(ID:{}), 소유자ID={}, 결과={}", username, currentUserId, ownerUserId, isOwner);
            
            return isOwner;
            
        } catch (Exception e) {
            log.error("소유자 확인 중 오류 발생", e);
            return false;
        }
    }
    
    /**
     * 객체에서 소유자 ID 추출 (리플렉션 기반)
     */
    private Long getOwnerIdFromObject(Object object, String ownerField) {
        try {
            // 1. 필드 직접 접근 시도
            Field field = findField(object.getClass(), ownerField);
            if (field != null) {
                field.setAccessible(true);
                Object value = field.get(object);
                return convertToLong(value);
            }
            
            // 2. Getter 메서드 접근 시도
            String getterName = "get" + ownerField.substring(0, 1).toUpperCase() + ownerField.substring(1);
            Method getter = object.getClass().getMethod(getterName);
            Object value = getter.invoke(object);
            return convertToLong(value);
            
        } catch (Exception e) {
            log.warn("소유자 필드 접근 실패: 필드={}, 객체={}", ownerField, object.getClass().getSimpleName(), e);
            return null;
        }
    }
    
    /**
     * 클래스 계층구조에서 필드 찾기
     */
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
    
    /**
     * 🔢 값을 Long으로 변환
     */
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
    
    /**
     * 👤 현재 사용자 ID 조회
     */
    private Long getCurrentUserId(String username) {
        try {
            Optional<Users> userOpt = userRepository.findByUsernameWithGroupsRolesAndPermissions(username);
            return userOpt.map(Users::getId).orElse(null);
        } catch (Exception e) {
            log.error("사용자 ID 조회 실패: {}", username, e);
            return null;
        }
    }

    /**
     * 👤 사용자의 모든 권한 조회 (DB 기반)
     */
    private Set<String> getUserPermissions(String username) {
        try {
            Optional<Users> userOpt = userRepository.findByUsernameWithGroupsRolesAndPermissions(username);
            if (userOpt.isEmpty()) {
                log.debug("사용자 없음: {}", username);
                return Set.of();
            }
            
            Users user = userOpt.get();
            Set<String> permissions = new HashSet<>(user.getPermissionNames());
            
            log.debug("👤 사용자 {} 권한 목록: {}", username, permissions);
            return permissions;
            
        } catch (Exception e) {
            log.error("사용자 권한 조회 실패: {}", username, e);
            return Set.of();
        }
    }

    /**
     * 🏷️ 권한명 생성 - 표준 패턴
     */
    private String buildPermissionName(String targetType, String action) {
        return String.format("%s_%s", targetType.toUpperCase(), action.toUpperCase());
    }

    /**
     * 도메인 객체에서 ID 추출
     */
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

    // ========= SpEL에서 호출 가능한 Public 헬퍼 메서드들 =========
    
    /**
     * SpEL용: ownerField 기반 소유자 확인
     * 사용 예: @customPermissionEvaluator.isOwner(authentication, #document, 'ownerId')
     */
    public boolean isOwner(Authentication authentication, Object targetObject, String ownerField) {
        return checkOwnership(authentication, targetObject, ownerField);
    }
}