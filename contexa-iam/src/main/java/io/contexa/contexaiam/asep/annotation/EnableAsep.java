package io.contexa.contexaiam.asep.annotation;

import io.contexa.contexaiam.asep.autoconfigure.AsepAutoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * ASEP (Aetherius Security Exception Protocol) 기능을 활성화합니다.
 * 이 어노테이션은 {@link AsepAutoConfiguration}을 임포트하여
 * 필요한 빈들을 자동으로 구성합니다.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AsepAutoConfiguration.class)
public @interface EnableAsep {
}