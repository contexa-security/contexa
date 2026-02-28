package io.contexa.contexacommon.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

/**
 * Enables AI Native Zero Trust security for legacy system integration.
 * <p>
 * Place this annotation on a {@code @SpringBootApplication} class to activate
 * the Contexa AI security infrastructure. This annotation creates a default
 * {@code PlatformConfig} (if none exists) using {@code IdentityDslRegistry},
 * which triggers the full Zero Trust configurer mechanism automatically.
 *
 * <h3>Usage:</h3>
 * <pre>{@code
 * @SpringBootApplication
 * @EnableAISecurity
 * public class LegacyApplication { }
 * }</pre>
 *
 * <p>Requires {@code spring-boot-starter-security} on the classpath.
 * Legacy systems must declare this dependency explicitly.</p>
 *
 * @see Protectable
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AiSecurityImportSelector.class)
public @interface EnableAISecurity {
}
