package io.contexa.autoconfigure.core.infra;

import io.contexa.contexacore.properties.ContexaSchedulerLockProperties;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

/**
 * Registers a Spring-managed {@link LockProvider} backed by the shedlock table
 * so every @Scheduled method annotated with @SchedulerLock acquires a
 * cluster-wide lock before running. Single-instance deployments keep working
 * without any functional difference because the lock always succeeds; when
 * multiple JVMs are added the same scheduler no longer fires in parallel.
 * <p>
 * The configuration activates automatically once ShedLock is on the classpath
 * and a DataSource is available. Operators can turn it off by setting
 * {@code contexa.scheduler.lock.enabled=false} during migration windows.
 * The default upper bound for unspecified locks is bound through
 * {@link ContexaSchedulerLockProperties#defaultLockAtMostFor}.
 */
@AutoConfiguration(after = DataSourceAutoConfiguration.class)
@ConditionalOnClass({LockProvider.class, JdbcTemplateLockProvider.class})
@ConditionalOnProperty(prefix = "contexa.scheduler.lock", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ContexaSchedulerLockProperties.class)
@EnableSchedulerLock(defaultLockAtMostFor = "PT5M")
public class CoreSchedulerLockAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(LockProvider.class)
    public LockProvider shedLockProvider(
            @Qualifier("contexaDataSource") DataSource dataSource,
            ContexaSchedulerLockProperties properties) {
        JdbcTemplateLockProvider.Configuration.Builder builder =
                JdbcTemplateLockProvider.Configuration.builder()
                        .withJdbcTemplate(new JdbcTemplate(dataSource));
        if (properties.useDatabaseTime()) {
            builder.usingDbTime();
        }
        return new JdbcTemplateLockProvider(builder.build());
    }
}
