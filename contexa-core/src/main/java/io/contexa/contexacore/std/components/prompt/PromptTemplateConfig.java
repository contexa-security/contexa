package io.contexa.contexacore.std.components.prompt;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface PromptTemplateConfig {
    String key();
    String[] aliases() default {};
    String description() default "";
}
