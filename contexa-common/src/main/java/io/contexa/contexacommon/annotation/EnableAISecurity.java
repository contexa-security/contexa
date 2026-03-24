package io.contexa.contexacommon.annotation;

import io.contexa.contexacommon.security.bridge.AuthObjectLocation;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

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
    /**
     * Security mode. SANDBOX is the default for legacy integration.
     */
    SecurityMode mode() default SecurityMode.SANDBOX;

    /**
     * Optional hint for authenticated object lookup in SANDBOX mode.
     */
    AuthObjectLocation authObjectLocation() default AuthObjectLocation.AUTO;

    /**
     * Optional attribute name for session/request attribute based handoff.
     */
    String authObjectAttribute() default "";

    /**
     * Optional authenticated object type hint for reflective extraction.
     */
    Class<?> authObjectType() default Object.class;
}
