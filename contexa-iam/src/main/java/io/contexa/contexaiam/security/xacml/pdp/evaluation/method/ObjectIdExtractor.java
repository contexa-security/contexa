package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import jakarta.persistence.Id;
import lombok.extern.slf4j.Slf4j;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

/**
 * 도메인 객체에서 Serializable ID를 추출하는 유틸리티 클래스
 */
@Slf4j
public class ObjectIdExtractor {

    /**
     * ID 필드로 가능한 이름들 (우선순위 순)
     */
    private static final List<String> ID_FIELD_NAMES = Arrays.asList(
            "id", "getId", "ID", "key", "getKey", "primaryKey", "getPrimaryKey"
    );

    /**
     * ID getter 메서드로 가능한 이름들 (우선순위 순)
     */
    private static final List<String> ID_GETTER_NAMES = Arrays.asList(
            "getId", "getKey", "getPrimaryKey", "id", "key", "primaryKey"
    );

    /**
     * 객체에서 Serializable ID를 추출합니다.
     *
     * @param targetObject 대상 객체
     * @return 추출된 Serializable ID, 실패 시 null
     */
    public static Serializable extractId(Object targetObject) {
        if (targetObject == null) {
            log.warn("ID 추출 실패: 대상 객체가 null입니다");
            return null;
        }

        log.debug("ID 추출 시작: 객체 타입 {}", targetObject.getClass().getSimpleName());

        try {
            // 1. JPA @Id 어노테이션으로 ID 필드 찾기
            Serializable id = extractIdByJpaAnnotation(targetObject);
            if (id != null) {
                log.debug("JPA @Id 어노테이션으로 ID 추출 성공: {}", id);
                return id;
            }

            // 2. Getter 메서드로 ID 추출
            id = extractIdByGetterMethod(targetObject);
            if (id != null) {
                log.debug("Getter 메서드로 ID 추출 성공: {}", id);
                return id;
            }

            // 3. 필드 직접 접근으로 ID 추출
            id = extractIdByFieldAccess(targetObject);
            if (id != null) {
                log.debug("필드 직접 접근으로 ID 추출 성공: {}", id);
                return id;
            }

            // 4. 객체 자체가 Serializable인 경우 (예: String, Long 등)
            if (targetObject instanceof Serializable) {
                log.debug("객체 자체가 Serializable: {}", targetObject);
                return (Serializable) targetObject;
            }

            log.warn("ID 추출 실패: 모든 방법 시도했으나 ID를 찾을 수 없습니다. 객체: {}",
                    targetObject.getClass().getSimpleName());
            return null;

        } catch (Exception e) {
            log.error("ID 추출 중 오류 발생: 객체 {}", targetObject.getClass().getSimpleName(), e);
            return null;
        }
    }

    /**
     * JPA @Id 어노테이션이 붙은 필드에서 ID 추출
     */
    private static Serializable extractIdByJpaAnnotation(Object targetObject) {
        Class<?> clazz = targetObject.getClass();

        // 모든 필드를 검사하여 @Id 어노테이션 찾기
        for (Field field : getAllFields(clazz)) {
            // JPA @Id 어노테이션 확인
            if (field.isAnnotationPresent(Id.class)){

                try {
                    field.setAccessible(true);
                    Object value = field.get(targetObject);

                    if (value instanceof Serializable) {
                        log.debug("@Id 어노테이션 필드에서 ID 발견: {} = {}", field.getName(), value);
                        return (Serializable) value;
                    }
                } catch (IllegalAccessException e) {
                    log.warn("@Id 필드 접근 실패: {}", field.getName(), e);
                }
            }
        }

        return null;
    }

    /**
     * Getter 메서드를 통해 ID 추출
     */
    private static Serializable extractIdByGetterMethod(Object targetObject) {
        Class<?> clazz = targetObject.getClass();

        // 우선순위에 따라 getter 메서드 시도
        for (String getterName : ID_GETTER_NAMES) {
            try {
                Method method = clazz.getMethod(getterName);
                Object value = method.invoke(targetObject);

                if (value instanceof Serializable) {
                    log.debug("Getter 메서드에서 ID 발견: {}() = {}", getterName, value);
                    return (Serializable) value;
                }
            } catch (Exception e) {
                // 메서드가 없거나 접근 실패 시 다음 방법 시도
                log.trace("Getter 메서드 실패: {}", getterName);
            }
        }

        return null;
    }

    /**
     * 필드 직접 접근을 통해 ID 추출
     */
    private static Serializable extractIdByFieldAccess(Object targetObject) {
        Class<?> clazz = targetObject.getClass();

        // 우선순위에 따라 필드명 시도
        for (String fieldName : ID_FIELD_NAMES) {
            try {
                Field field = findField(clazz, fieldName);
                if (field != null) {
                    field.setAccessible(true);
                    Object value = field.get(targetObject);

                    if (value instanceof Serializable) {
                        log.debug("필드에서 ID 발견: {} = {}", fieldName, value);
                        return (Serializable) value;
                    }
                }
            } catch (Exception e) {
                log.trace("필드 접근 실패: {}", fieldName);
            }
        }

        return null;
    }

    /**
     * 클래스 계층구조에서 모든 필드를 가져옵니다 (상속된 필드 포함)
     */
    private static Field[] getAllFields(Class<?> clazz) {
        if (clazz == null || clazz == Object.class) {
            return new Field[0];
        }

        // 현재 클래스의 필드와 부모 클래스의 필드를 합침
        Field[] currentFields = clazz.getDeclaredFields();
        Field[] parentFields = getAllFields(clazz.getSuperclass());

        Field[] allFields = new Field[currentFields.length + parentFields.length];
        System.arraycopy(currentFields, 0, allFields, 0, currentFields.length);
        System.arraycopy(parentFields, 0, allFields, currentFields.length, parentFields.length);

        return allFields;
    }

    /**
     * 클래스 계층구조에서 특정 이름의 필드를 찾습니다
     */
    private static Field findField(Class<?> clazz, String fieldName) {
        if (clazz == null || clazz == Object.class) {
            return null;
        }

        try {
            return clazz.getDeclaredField(fieldName);
        } catch (NoSuchFieldException e) {
            // 부모 클래스에서 찾기
            return findField(clazz.getSuperclass(), fieldName);
        }
    }

    /**
     * 특정 도메인 객체 타입별 ID 추출 (타입 안전성을 위한 오버로드)
     */
    public static Long extractLongId(Object targetObject) {
        Serializable id = extractId(targetObject);
        if (id instanceof Long) {
            return (Long) id;
        } else if (id instanceof Number) {
            return ((Number) id).longValue();
        } else if (id instanceof String) {
            try {
                return Long.parseLong((String) id);
            } catch (NumberFormatException e) {
                log.warn("String ID를 Long으로 변환 실패: {}", id);
                return null;
            }
        }
        return null;
    }

    /**
     * 특정 도메인 객체 타입별 ID 추출 (타입 안전성을 위한 오버로드)
     */
    public static String extractStringId(Object targetObject) {
        Serializable id = extractId(targetObject);
        return id != null ? id.toString() : null;
    }

    /**
     * ID 추출 가능 여부 확인
     */
    public static boolean canExtractId(Object targetObject) {
        return extractId(targetObject) != null;
    }

    /**
     * 객체의 타입과 ID 정보를 포함한 식별자 문자열 생성
     */
    public static String createObjectIdentifier(Object targetObject) {
        if (targetObject == null) {
            return "null";
        }

        Serializable id = extractId(targetObject);
        String className = targetObject.getClass().getSimpleName();

        if (id != null) {
            return String.format("%s[id=%s]", className, id);
        } else {
            return String.format("%s[hashCode=%d]", className, targetObject.hashCode());
        }
    }
}