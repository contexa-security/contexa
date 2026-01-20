package io.contexa.contexaidentity.security.core.asep.annotation;

import org.springframework.core.Ordered;

import java.lang.annotation.*;


@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SecurityExceptionHandler {
    
    Class<? extends Throwable>[] value() default {};

    
    int priority() default Ordered.LOWEST_PRECEDENCE;

    
    String[] produces() default {};
}
