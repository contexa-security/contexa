package io.contexa.autoconfigure.core.scope.sample;

import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

/** A bean of a Contexa package (this package stands in for a Contexa library) with the same annotations, as Contexa writes them. */
@CacheConfig(cacheManager = "contexaCacheManager")
public class ContexaSample {

    private final AtomicInteger ticks = new AtomicInteger();
    private final AtomicInteger cacheCalls = new AtomicInteger();

    @Scheduled(fixedRate = 50)
    public void tick() {
        ticks.incrementAndGet();
    }

    @Async("contexaTaskExecutor")
    public CompletableFuture<String> thread() {
        return CompletableFuture.completedFuture(Thread.currentThread().getName());
    }

    @Cacheable("contexaCache")
    public String cached(String key) {
        cacheCalls.incrementAndGet();
        return key;
    }

    /** The same cache name and the same key as the application's method of the same kind. */
    @Cacheable("shared")
    public String shared(String key) {
        return "contexa:" + key;
    }

    public int ticks() {
        return ticks.get();
    }

    public int cacheCalls() {
        return cacheCalls.get();
    }

    @Configuration(proxyBeanMethods = false)
    public static class Definition {

        @Bean
        ContexaSample contexaSample() {
            return new ContexaSample();
        }

        /** The executor of the asynchronous methods of Contexa. */
        @Bean(name = "contexaTaskExecutor", defaultCandidate = false)
        Executor contexaTaskExecutor() {
            ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
            executor.setThreadNamePrefix("contexa-async-");
            executor.setCorePoolSize(1);
            executor.initialize();
            return executor;
        }
    }
}
