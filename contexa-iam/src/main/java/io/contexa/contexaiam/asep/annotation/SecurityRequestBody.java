package io.contexa.contexaiam.asep.annotation;

import java.lang.annotation.*;

/**
 * ASEP 예외 핸들러 메소드의 파라미터에 사용하여 HTTP 요청 본문을 역직렬화하여 주입받습니다.
 * HttpMessageConverter를 사용합니다.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SecurityRequestBody {
    boolean required() default true;
}
