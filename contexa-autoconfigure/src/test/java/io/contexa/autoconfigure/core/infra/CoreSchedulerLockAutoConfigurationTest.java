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

import com.legacyshop.scope.LegacySchedulerLockApplication;
import com.legacyshop.scope.LegacySchedulerLockApplication.HostJobs;
import com.legacyshop.scope.LegacySchedulerLockApplication.RecordingLockProvider;
import io.contexa.autoconfigure.core.ContexaProxyModeAutoConfiguration;
import io.contexa.autoconfigure.core.scope.ContexaSchedulerLockAnnotationBeanPostProcessor;
import io.contexa.autoconfigure.core.scope.ContexaScopedAnnotationAutoConfiguration;
import io.contexa.contexacommon.security.HeldBean;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.Advised;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.scheduling.annotation.Scheduled;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The scheduled work of Contexa takes its locks in Contexa's own lock store, by the name of Contexa's lock provider, and
 * the application's {@code @SchedulerLock} methods are left as the application left them (R-9 of
 * docs/agent/운영모드-정상화-구현계획.md): dormant when it never turned ShedLock on, locked by its own provider only when
 * it did. The application's lookups of a lock provider never find Contexa's.
 */
class CoreSchedulerLockAutoConfigurationTest {

    static final String CONTEXA_LOCK_PROVIDER = "contexaShedLockProvider";

    static ApplicationContextRunner runner(Class<?>... configurations) {
        return new ApplicationContextRunner()
                .withUserConfiguration(configurations)
                .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class,
                        ContexaProxyModeAutoConfiguration.class, ContexaScopedAnnotationAutoConfiguration.class,
                        CoreSchedulerLockAutoConfiguration.class));
    }

    @Test
    @DisplayName("앱에 LockProvider가 있어도 Contexa 잠금 제공자는 Contexa 이름으로 만들어지고, 앱의 타입 조회에는 앱 것만 보인다")
    void contexasLockProviderIsMadeBesideTheApplicationsAndHiddenFromItsLookups() {
        runner(LegacySchedulerLockApplication.Dormant.class, ContexaDatabase.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.containsBean(CONTEXA_LOCK_PROVIDER)).as("Contexa's lock provider, by its name").isTrue();
            Object held = context.getBean(CONTEXA_LOCK_PROVIDER);
            assertThat(held).isInstanceOf(HeldBean.class);
            assertThat(((HeldBean<?>) held).get()).as("the provider of Contexa's lock table")
                    .isInstanceOf(JdbcTemplateLockProvider.class);
            assertThat(context.getBeanNamesForType(LockProvider.class)).as("the lock providers the application can find")
                    .containsExactly("hostLockProvider");
            assertThat(context.getBeanProvider(LockProvider.class).getIfUnique())
                    .isSameAs(context.getBean("hostLockProvider"));
        });
    }

    @Test
    @DisplayName("LockProvider가 없는 앱의 타입 조회는 Contexa 잠금 제공자를 찾지 않는다")
    void anApplicationWithoutALockProviderFindsNoneOfContexas() {
        runner(LegacySchedulerLockApplication.DormantWithoutProvider.class, ContexaDatabase.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.containsBean(CONTEXA_LOCK_PROVIDER)).isTrue();
            assertThat(context.getBeanProvider(LockProvider.class).getIfAvailable())
                    .as("ShedLock of the application, Spring and the application's code look a provider up by type").isNull();
        });
    }

    @Test
    @DisplayName("ShedLock을 켜지 않은 앱의 @SchedulerLock 메서드는 Contexa 때문에 잠기지 않는다")
    void theApplicationsDormantSchedulerLockStaysDormant() {
        runner(LegacySchedulerLockApplication.Dormant.class, ContexaDatabase.class, RecordedContexaLocks.class).run(context -> {
            assertThat(context).hasNotFailed();
            HostJobs host = context.getBean(HostJobs.class);

            host.nightly();

            assertThat(host.runs()).isEqualTo(1);
            assertThat(context.getBean("hostLockProvider", RecordingLockProvider.class).names())
                    .as("the application never turned ShedLock on: its own provider is not asked").isEmpty();
            assertThat(contexaRecorder(context).names()).as("nor is Contexa's").isEmpty();
        });
    }

    @Test
    @DisplayName("앱에 LockProvider가 있어도 Contexa의 @SchedulerLock 메서드는 Contexa 잠금 제공자로 잠근다")
    void contexasLockedMethodTakesContexasLockBesideTheApplicationsProvider() {
        runner(LegacySchedulerLockApplication.Dormant.class, ContexaDatabase.class, RecordedContexaLocks.class,
                ContexaJobsDefinition.class).run(context -> {
            assertThat(context).hasNotFailed();
            ContexaJobs jobs = context.getBean(ContexaJobs.class);

            jobs.retention();
            jobs.unbounded();

            assertThat(jobs.runs()).isEqualTo(2);
            List<LockConfiguration> locks = contexaRecorder(context).configurations();
            assertThat(locks).extracting(LockConfiguration::getName)
                    .containsExactly(ContexaJobs.LOCK, ContexaJobs.UNBOUNDED_LOCK);
            assertThat(locks.get(0).getLockAtMostFor()).as("the annotation's upper bound").isEqualTo(Duration.ofMinutes(1));
            assertThat(locks.get(0).getLockAtLeastFor()).isEqualTo(Duration.ZERO);
            assertThat(locks.get(1).getLockAtMostFor()).as("no upper bound named: five minutes, as before")
                    .isEqualTo(Duration.ofMinutes(5));
            assertThat(locks.get(1).getLockAtLeastFor()).isEqualTo(Duration.ZERO);
            assertThat(context.getBean("hostLockProvider", RecordingLockProvider.class).names())
                    .as("the application's store is not asked for Contexa's lock").isEmpty();
        });
    }

    @Test
    @DisplayName("앱이 ShedLock을 켜면 앱 메서드는 앱 제공자로만, Contexa 메서드는 Contexa 제공자로 한 번만 잠근다")
    void anApplicationThatTurnedShedLockOnLocksItsOwnMethodsAndNeverContexasInItsStore() {
        runner(LegacySchedulerLockApplication.Enabled.class, ContexaDatabase.class, RecordedContexaLocks.class,
                ContexaJobsDefinition.class).run(context -> {
            assertThat(context).hasNotFailed();
            ContexaJobs jobs = context.getBean(ContexaJobs.class);
            HostJobs host = context.getBean(HostJobs.class);

            jobs.retention();
            host.nightly();

            assertThat(jobs.runs()).isEqualTo(1);
            assertThat(host.runs()).isEqualTo(1);
            assertThat(contexaRecorder(context).names()).as("Contexa's lock, once, in Contexa's store")
                    .containsExactly(ContexaJobs.LOCK);
            assertThat(context.getBean("hostLockProvider", RecordingLockProvider.class).names())
                    .as("the application's lock in the application's store, and Contexa's never")
                    .containsExactly(LegacySchedulerLockApplication.HOST_LOCK);
            assertThat(jobs).isInstanceOf(Advised.class);
            List<String> advisors = Arrays.stream(((Advised) jobs).getAdvisors())
                    .map(advisor -> advisor.getAdvice().getClass().getName()).toList();
            assertThat(advisors).as("the application's ShedLock reaches Contexa's method as well, behind Contexa's lock")
                    .hasSize(2);
            assertThat(advisors.get(0)).as("Contexa's lock is taken first")
                    .startsWith(ContexaSchedulerLockAnnotationBeanPostProcessor.class.getName());
            assertThat(advisors.get(1)).as("ShedLock's own interceptor, of the application")
                    .startsWith("net.javacrumbs.shedlock.spring.aop.");
        });
    }

    @Test
    @DisplayName("Contexa의 예약 작업은 실행될 때 Contexa 잠금을 거친다")
    void contexasScheduledLockedMethodRunsUnderContexasLock() {
        runner(LegacySchedulerLockApplication.Dormant.class, ContexaDatabase.class, RecordedContexaLocks.class,
                ContexaScheduledJobsDefinition.class).run(context -> {
            assertThat(context).hasNotFailed();
            ContexaScheduledJobs jobs = context.getBean(ContexaScheduledJobs.class);
            Thread.sleep(500);
            int ticks = jobs.ticks();
            List<String> locks = contexaRecorder(context).names();

            assertThat(ticks).as("the scheduled method ran").isGreaterThan(0);
            assertThat(locks).as("each run took Contexa's lock first").containsOnly(ContexaScheduledJobs.LOCK)
                    .hasSizeGreaterThanOrEqualTo(ticks);
            assertThat(context.getBean("hostLockProvider", RecordingLockProvider.class).names()).isEmpty();
        });
    }

    private static RecordingLockProvider contexaRecorder(ApplicationContext context) {
        return (RecordingLockProvider) ((HeldBean<?>) context.getBean(CONTEXA_LOCK_PROVIDER)).get();
    }

    /** Contexa's database; these tests never reach it (a provider that records stands in, or none is asked). */
    @Configuration(proxyBeanMethods = false)
    static class ContexaDatabase {

        @Bean(name = "contexaDataSource", defaultCandidate = false)
        DataSource contexaDataSource() {
            return new DriverManagerDataSource("jdbc:postgresql://127.0.0.1:1/unused");
        }
    }

    /** Contexa's lock provider, replaced under its name by one that records the names it was asked for. */
    @Configuration(proxyBeanMethods = false)
    static class RecordedContexaLocks {

        @Bean(name = CONTEXA_LOCK_PROVIDER)
        HeldBean<LockProvider> contexaShedLockProvider() {
            return new HeldBean<>(new RecordingLockProvider());
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ContexaJobsDefinition {

        @Bean
        ContexaJobs contexaJobs() {
            return new ContexaJobs();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ContexaScheduledJobsDefinition {

        @Bean
        ContexaScheduledJobs contexaScheduledJobs() {
            return new ContexaScheduledJobs();
        }
    }

    /** A job of Contexa's (a class of a Contexa package) that names a lock, as the retention jobs do. */
    public static class ContexaJobs {

        static final String LOCK = "contexaRetentionSample";
        static final String UNBOUNDED_LOCK = "contexaUnboundedSample";

        private final AtomicInteger runs = new AtomicInteger();

        @SchedulerLock(name = LOCK, lockAtMostFor = "PT1M", lockAtLeastFor = "PT0S")
        public void retention() {
            runs.incrementAndGet();
        }

        @SchedulerLock(name = UNBOUNDED_LOCK)
        public void unbounded() {
            runs.incrementAndGet();
        }

        public int runs() {
            return runs.get();
        }
    }

    /** A scheduled job of Contexa's that names a lock. */
    public static class ContexaScheduledJobs {

        static final String LOCK = "contexaScheduledSample";

        private final AtomicInteger ticks = new AtomicInteger();

        @Scheduled(fixedRate = 50)
        @SchedulerLock(name = LOCK, lockAtMostFor = "PT1M")
        public void tick() {
            ticks.incrementAndGet();
        }

        public int ticks() {
            return ticks.get();
        }
    }
}
