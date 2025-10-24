package io.contexa.contexaiam.asep.annotation;

import java.lang.annotation.*;

/**
 * ASEP 예외 핸들러 메소드의 파라미터에 사용하여 현재 인증된 사용자의 Principal 객체를 주입받습니다.
 * Authentication.getPrincipal()의 결과입니다.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SecurityPrincipal {
}
