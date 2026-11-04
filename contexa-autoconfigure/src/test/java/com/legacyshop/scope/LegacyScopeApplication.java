package com.legacyshop.scope;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

/** A legacy application (a package that is not Contexa's) with annotations it may or may not have turned on. */
public class LegacyScopeApplication {

    public static class AppService {

        private final AtomicInteger ticks = new AtomicInteger();
        private final AtomicInteger cacheCalls = new AtomicInteger();

        @Scheduled(fixedRate = 50)
        public void tick() {
            ticks.incrementAndGet();
        }

        @Async
        public CompletableFuture<String> thread() {
            return CompletableFuture.completedFuture(Thread.currentThread().getName());
        }

        @Cacheable("legacyCache")
        public String cached(String key) {
            cacheCalls.incrementAndGet();
            return key;
        }

        /** The same cache name and the same key as the Contexa sample: the two must never meet. */
        @Cacheable("shared")
        public String shared(String key) {
            return "app:" + key;
        }

        public int ticks() {
            return ticks.get();
        }

        public int cacheCalls() {
            return cacheCalls.get();
        }
    }

    /** The application's own scheduling configuration: only the application's scheduling support may ever call it, and once. */
    public static class CountingSchedulingConfigurer implements SchedulingConfigurer {

        private final AtomicInteger calls = new AtomicInteger();

        @Override
        public void configureTasks(ScheduledTaskRegistrar registrar) {
            calls.incrementAndGet();
        }

        public int calls() {
            return calls.get();
        }
    }

    /** Application code that asks for "a cache manager, if there is one" and acts on the answer. */
    public static class CacheManagerConsumer {

        private final CacheManager viaProvider;
        private final CacheManager viaInjection;

        public CacheManagerConsumer(ObjectProvider<CacheManager> provider, @Nullable CacheManager injected) {
            this.viaProvider = provider.getIfAvailable();
            this.viaInjection = injected;
        }

        public CacheManager viaProvider() {
            return viaProvider;
        }

        public CacheManager viaInjection() {
            return viaInjection;
        }
    }

    /** Nothing enabled: the annotations are dormant. */
    @Configuration(proxyBeanMethods = false)
    public static class Dormant {
        @Bean
        AppService appService() {
            return new AppService();
        }

        @Bean
        CountingSchedulingConfigurer schedulingConfigurer() {
            return new CountingSchedulingConfigurer();
        }

        @Bean
        CacheManagerConsumer cacheManagerConsumer(ObjectProvider<CacheManager> provider, @Nullable CacheManager injected) {
            return new CacheManagerConsumer(provider, injected);
        }
    }

    /** The application's own marker for asynchronous methods. */
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface AppAsync {
    }

    /** The application turned asynchronous execution on for its own marker only; {@code @Async} is not what its support looks at. */
    @Configuration(proxyBeanMethods = false)
    @EnableAsync(annotation = AppAsync.class)
    public static class AsyncForItsOwnMarker {
        @Bean
        AppService appService() {
            return new AppService();
        }
    }

    /** The application that turned scheduling and asynchronous execution on itself. */
    @Configuration(proxyBeanMethods = false)
    @EnableScheduling
    @EnableAsync
    public static class Enabled {
        @Bean
        AppService appService() {
            return new AppService();
        }

        @Bean
        CountingSchedulingConfigurer schedulingConfigurer() {
            return new CountingSchedulingConfigurer();
        }
    }

    /** The application that turned caching on itself (Spring Boot gives it a cache manager). */
    @Configuration(proxyBeanMethods = false)
    @EnableCaching
    public static class CachingEnabled {
        @Bean
        AppService appService() {
            return new AppService();
        }
    }
}
