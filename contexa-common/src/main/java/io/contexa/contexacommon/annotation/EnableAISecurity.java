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
 * Legacy security remains untouched. Only {@link Protectable} resources are protected.
 * <pre>{@code
 * @EnableAISecurity(
 *     mode = SecurityMode.SANDBOX
 * )
 * @SpringBootApplication
 * public class LegacyApplication { }
 * }</pre>
 *
 * @see Protectable
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

}
