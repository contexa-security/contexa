package io.contexa.contexacommon.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * [재설계]
 * 동적 인가 정책의 대상이 되는 서비스 계층의 메서드를 명시적으로 지정하고,
 * 해당 메서드에 필요한 '비즈니스 권한 이름'을 선언합니다.
 * MethodResourceScanner는 이 어노테이션이 붙은 메서드만 스캔합니다.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Protectable {

    /**
     * 소유자 확인을 위한 엔티티 필드명
     * 예: "ownerId", "createdBy", "userId"
     * 이 필드가 지정되면 해당 객체의 소유자 확인이 자동으로 수행됩니다.
     * @return 소유자 필드명
     */
    String ownerField() default "";
}