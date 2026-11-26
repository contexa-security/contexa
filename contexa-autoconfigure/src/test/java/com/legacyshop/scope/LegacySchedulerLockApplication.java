package com.legacyshop.scope;

import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.core.SimpleLock;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A legacy application (a package that is not Contexa's) with a {@code @SchedulerLock} method, which it may or may not
 * have turned ShedLock on for, and a lock provider of its own or none.
 */
public class LegacySchedulerLockApplication {

    /** The lock name of the application's method. */
    public static final String HOST_LOCK = "legacyNightlyJob";

    /** A service of the application whose method names a lock. */
    public static class HostJobs {

        private final AtomicInteger runs = new AtomicInteger();

        @SchedulerLock(name = HOST_LOCK, lockAtMostFor = "PT1M")
        public void nightly() {
            runs.incrementAndGet();
        }

        public int runs() {
            return runs.get();
        }
    }

    /** A lock provider that grants every lock and remembers the names it was asked for. */
    public static class RecordingLockProvider implements LockProvider {

        private final List<LockConfiguration> configurations = new CopyOnWriteArrayList<>();

        @Override
        public Optional<SimpleLock> lock(LockConfiguration lockConfiguration) {
            configurations.add(lockConfiguration);
            return Optional.of(() -> {
            });
        }

        public List<String> names() {
            return configurations.stream().map(LockConfiguration::getName).toList();
        }

        public List<LockConfiguration> configurations() {
            return configurations;
        }
    }

    /** The application left ShedLock off and has a lock provider of its own. */
    @Configuration(proxyBeanMethods = false)
    public static class Dormant {

        @Bean
        HostJobs hostJobs() {
            return new HostJobs();
        }

        @Bean
        RecordingLockProvider hostLockProvider() {
            return new RecordingLockProvider();
        }
    }

    /** The application left ShedLock off and has no lock provider. */
    @Configuration(proxyBeanMethods = false)
    public static class DormantWithoutProvider {

        @Bean
        HostJobs hostJobs() {
            return new HostJobs();
        }
    }

    /** The application turned ShedLock on itself, with a lock provider of its own. */
    @Configuration(proxyBeanMethods = false)
    @EnableSchedulerLock(defaultLockAtMostFor = "PT1M")
    public static class Enabled {

        @Bean
        HostJobs hostJobs() {
            return new HostJobs();
        }

        @Bean
        RecordingLockProvider hostLockProvider() {
            return new RecordingLockProvider();
        }
    }
}
