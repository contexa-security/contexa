package io.contexa.contexaiam.asep.annotation;

import org.springframework.core.Ordered;

import java.lang.annotation.*;

/**
 * ASEP 필터 체인에서 발생하는 예외를 처리하는 메소드에 지정합니다.
 * Spring MVC 의 @ExceptionHandler와 유사한 역할을 합니다.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SecurityExceptionHandler {
    /**
     * 이 핸들러가 처리할 예외 타입들. 명시하지 않으면 메소드 시그니처의 첫 번째 Throwable 파라미터로 추론.
     */
    Class<? extends Throwable>[] value() default {};

    /**
     * 핸들러 우선순위. 낮은 값일수록 높은 우선순위를 가집니다.
     * 기본값은 가장 낮은 우선순위입니다.
     */
    int priority() default Ordered.LOWEST_PRECEDENCE;

    /**
     * 이 핸들러가 생성할 수 있는 미디어 타입 (Content Negotiation 용도).
     * 예: "application/json", "application/xml"
     */
    String[] produces() default {};
}
