package io.contexa.showcase.business;

import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Installs the business part of a workload ({@link BusinessConfiguration}). Requires the property showcase.control.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(BusinessConfiguration.class)
public @interface EnableShowcaseBusiness {
}
