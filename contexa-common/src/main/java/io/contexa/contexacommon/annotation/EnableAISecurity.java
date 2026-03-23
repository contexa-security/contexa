package io.contexa.contexacommon.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import io.contexa.contexacommon.security.bridge.old.AuthBridge;
import io.contexa.contexacommon.security.bridge.old.NoOpAuthBridge;
import io.contexa.contexacommon.security.bridge.old.SecurityMode;
import org.springframework.context.annotation.Import;

/**
 * Enables AI Native Zero Trust security.
 * <p>
 * <b>FULL mode</b> (default): Contexa manages entire authentication and authorization.
 * For new projects or systems where Contexa is the primary security provider.
 * <pre>{@code
 * @EnableAISecurity
 * @SpringBootApplication
 * public class NewApplication { }
 * }</pre>
 *
 * <b>SANDBOX mode</b>: Contexa operates alongside existing legacy security.
 * Legacy authentication is bridged into Contexa via {@link AuthBridge}.
 * Legacy security remains untouched. Only {@link Protectable} resources are protected.
 * <pre>{@code
 * @EnableAISecurity(
 *     mode = SecurityMode.SANDBOX,
 *     authBridge = SessionAuthBridge.class,
 *     sessionUserAttribute = "loginUser"
 * )
 * @SpringBootApplication
 * public class LegacyApplication { }
 * }</pre>
 *
 * @see Protectable
 * @see AuthBridge
 * @see SecurityMode
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AiSecurityImportSelector.class)
public @interface EnableAISecurity {

    /**
     * Security mode. FULL for new projects, SANDBOX for legacy integration.
     */
    SecurityMode mode() default SecurityMode.FULL;

    /**
     * Authentication bridge class for SANDBOX mode.
     * Extracts user identity from legacy authentication mechanism (session, JWT, cookie, etc.)
     * and converts it into Spring Security Authentication for Contexa to use.
     */
    Class<? extends AuthBridge> authBridge() default NoOpAuthBridge.class;

    /**
     * Session attribute name that stores the legacy user object.
     * Used by SessionAuthBridge. Ignored if authBridge is not SessionAuthBridge.
     */
    String sessionUserAttribute() default "";

    /**
     * JWT secret key for JwtAuthBridge. Ignored if authBridge is not JwtAuthBridge.
     */
    String jwtSecret() default "";

    /**
     * Cookie name for CookieAuthBridge. Ignored if authBridge is not CookieAuthBridge.
     */
    String authCookieName() default "";
}
