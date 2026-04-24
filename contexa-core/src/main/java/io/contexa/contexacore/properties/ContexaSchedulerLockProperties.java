package io.contexa.contexacore.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Configuration surface for the Contexa ShedLock auto-configuration.
 * <p>
 * Operators bind these values under {@code contexa.scheduler.lock} in their
 * application configuration. Defaults keep ShedLock active so multi-JVM
 * deployments are safe out of the box. Single-instance deployments may keep
 * the default because the lock always succeeds and the overhead is
 * negligible.
 *
 * @param enabled              Whether the ShedLock auto-configuration registers
 *                             a {@code LockProvider} bean. Setting this to
 *                             {@code false} disables every
 *                             {@code @SchedulerLock} and each
 *                             {@code @Scheduled} method reverts to
 *                             single-JVM-only exclusivity.
 * @param defaultLockAtMostFor Fallback upper bound applied when a specific
 *                             scheduler omits {@code lockAtMostFor}. Prevents
 *                             stuck locks from surviving indefinitely after a
 *                             JVM crash.
 * @param useDatabaseTime      When true the {@code JdbcTemplateLockProvider}
 *                             uses {@code now()} from the database engine so
 *                             every instance sees the same clock. When false
 *                             the provider falls back to the JVM clock, which
 *                             can simplify local H2 tests whose database
 *                             timezone is not aligned with the JVM.
 */
@ConfigurationProperties(prefix = "contexa.scheduler.lock")
public record ContexaSchedulerLockProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("5m") Duration defaultLockAtMostFor,
        @DefaultValue("true") boolean useDatabaseTime) {
}
