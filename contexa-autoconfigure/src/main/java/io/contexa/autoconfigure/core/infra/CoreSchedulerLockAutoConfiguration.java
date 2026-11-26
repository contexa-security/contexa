/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.core.infra;

import io.contexa.autoconfigure.core.ContexaOwnBeans;
import io.contexa.autoconfigure.core.scope.ContexaSchedulerLockAnnotationBeanPostProcessor;
import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexacore.properties.ContexaSchedulerLockProperties;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.time.Duration;

/**
 * The cluster-wide locks of the scheduled work of Contexa: every {@code @SchedulerLock} method of Contexa's classes takes
 * its lock in Contexa's lock table ({@code ctxa_shedlock}, on Contexa's data source) before it runs. Single-instance
 * deployments keep working without any functional difference because the lock always succeeds; when multiple JVMs are
 * added the same scheduler no longer fires in parallel.
 * <p>
 * The locks are Contexa's alone (R-9 of docs/agent/운영모드-정상화-구현계획.md). Contexa does not turn ShedLock on for the
 * application ({@code @EnableSchedulerLock}): a processor applies the annotation to Contexa's classes only
 * ({@link ContexaSchedulerLockAnnotationBeanPostProcessor}). Contexa's lock provider is always made, an application that
 * has a lock provider of its own included, and it is held ({@link HeldBean}) under its name, so that the application's
 * lookups of a lock provider by type, ShedLock's of the application among them, never find it, and Contexa's code takes it
 * by that name. The lock names are those of the annotations, unprefixed: Contexa's table holds Contexa's locks only.
 * <p>
 * The configuration activates once ShedLock is on the classpath and Contexa's data source is available. Operators can
 * turn it off by setting {@code contexa.scheduler.lock.enabled=false} during migration windows. A bean of the name
 * {@value #LOCK_PROVIDER} (a {@link HeldBean} of a lock provider, or a lock provider) replaces Contexa's lock provider.
 */
@AutoConfiguration(after = DataSourceAutoConfiguration.class)
@ConditionalOnClass({LockProvider.class, JdbcTemplateLockProvider.class})
@ConditionalOnBean(name = "contexaDataSource")
@ConditionalOnProperty(prefix = "contexa.scheduler.lock", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ContexaSchedulerLockProperties.class)
public class CoreSchedulerLockAutoConfiguration {

    /** The name of Contexa's lock provider, a {@link HeldBean} of a {@link LockProvider}. */
    public static final String LOCK_PROVIDER = "contexaShedLockProvider";

    /** ShedLock's default table name is {@code shedlock}; a table of the application may have it, so Contexa's has the prefix. */
    static final String LOCK_TABLE = "ctxa_shedlock";

    /**
     * The upper bound of a lock whose annotation names none, the one Contexa's {@code @EnableSchedulerLock} gave. The
     * property {@code contexa.scheduler.lock.default-lock-at-most-for} is not read, as before.
     */
    static final Duration DEFAULT_LOCK_AT_MOST_FOR = Duration.ofMinutes(5);

    @Bean(name = LOCK_PROVIDER)
    @ConditionalOnMissingBean(name = LOCK_PROVIDER)
    public HeldBean<LockProvider> shedLockProvider(
            @Qualifier("contexaDataSource") DataSource dataSource,
            ContexaSchedulerLockProperties properties) {
        JdbcTemplateLockProvider.Configuration.Builder builder =
                JdbcTemplateLockProvider.Configuration.builder()
                        .withJdbcTemplate(new JdbcTemplate(dataSource))
                        .withTableName(LOCK_TABLE);
        if (properties.useDatabaseTime()) {
            builder.usingDbTime();
        }
        return new HeldBean<>(new JdbcTemplateLockProvider(builder.build()));
    }

    /**
     * The locks of Contexa's {@code @SchedulerLock} methods, with Contexa's lock provider by its name. A lock whose
     * annotation names no upper bound is held at most {@link #DEFAULT_LOCK_AT_MOST_FOR}.
     */
    @Bean(name = "contexaSchedulerLockAnnotationProcessor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static ContexaSchedulerLockAnnotationBeanPostProcessor contexaSchedulerLockAnnotationProcessor(BeanFactory beanFactory) {
        return new ContexaSchedulerLockAnnotationBeanPostProcessor(
                () -> ContexaOwnBeans.own(beanFactory, LOCK_PROVIDER, LockProvider.class), DEFAULT_LOCK_AT_MOST_FOR);
    }
}
