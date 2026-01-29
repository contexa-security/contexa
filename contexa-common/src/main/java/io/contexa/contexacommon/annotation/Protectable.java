package io.contexa.contexacommon.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Protectable {


    String ownerField() default "";
    AnalysisRequirement analysisRequirement() default AnalysisRequirement.PREFERRED;
    long analysisTimeout() default 5000;
    String defaultAction() default "ALLOW";
}