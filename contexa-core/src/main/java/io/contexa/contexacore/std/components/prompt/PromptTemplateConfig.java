package io.contexa.contexacore.std.components.prompt;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * OCP 준수: 프롬프트 템플릿 설정 어노테이션
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface PromptTemplateConfig {
    String key();
    String[] aliases() default {};
    String description() default "";
}
