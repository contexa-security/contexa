package io.contexa.contexaiam.asep.annotation;

import org.springframework.web.bind.annotation.ResponseBody;

import java.lang.annotation.*;

/**
 * ASEP 예외 핸들러 메소드 또는 @SecurityControllerAdvice 클래스 레벨에 사용하여
 * 반환 값을 HTTP 응답 본문으로 직렬화하도록 지정합니다. HttpMessageConverter를 사용합니다.
 * Spring MVC 의 @ResponseBody와 유사한 역할을 하며, HttpMessageConverter 선택 로직 등을 활용합니다.
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@ResponseBody // Spring의 HttpMessageConverter 선택 로직 등을 활용하기 위해 메타 어노테이션으로 사용
public @interface SecurityResponseBody {
}
