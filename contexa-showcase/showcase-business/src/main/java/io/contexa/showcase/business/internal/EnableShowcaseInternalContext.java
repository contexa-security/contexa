package io.contexa.showcase.business.internal;

import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Installs {@link InternalContextFilter} in a workload. Requires the property showcase.internal.signing-key
 * (base64, at least 32 bytes); the application fails to start without it.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(InternalContextConfiguration.class)
public @interface EnableShowcaseInternalContext {
}
