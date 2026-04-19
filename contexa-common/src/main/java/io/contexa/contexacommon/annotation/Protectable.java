package io.contexa.contexacommon.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Protectable {
    String ownerField() default "";
    String resourceId() default "";
    String resourceUrl() default "";
    String httpMethod() default "";
    String criticality() default "standard";
    boolean verificationRequired() default true;
    boolean sync() default false;
}
