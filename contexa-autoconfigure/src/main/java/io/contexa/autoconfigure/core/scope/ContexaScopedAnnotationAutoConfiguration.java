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
package io.contexa.autoconfigure.core.scope;

import io.contexa.contexacommon.cache.ContexaCaffeine;

import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;
import org.springframework.core.env.Environment;

import java.time.Duration;
import java.util.concurrent.Executor;

/**
 * Scheduling, asynchronous execution and caching for Contexa's own beans, and for them only.
 * <p>
 * Contexa used to switch these on for the whole application ({@code @EnableScheduling}, {@code @EnableAsync}, {@code @EnableCaching}), which
 * made the application's dormant {@code @Scheduled}, {@code @Async} and {@code @Cacheable} methods start to run, run on another thread, and
 * cache. Each support is now a post-processor that looks at Contexa's classes only. When the application turned the support on itself, its
 * own processor already handles Contexa's beans and Contexa's stands aside; that is decided when a bean is processed, in the context of
 * the bean (a registration condition would look at the parent contexts too, and the order of auto-configurations would matter).
 */
@AutoConfiguration
public class ContexaScopedAnnotationAutoConfiguration {

    public static final String TASK_SCHEDULER = "contexaTaskScheduler";

    private static final int CONTEXA_SCHEDULER_THREADS = 4;

    /**
     * Every {@code @Scheduled} of Contexa names this scheduler, so that it runs here whoever processes it: an application
     * that turns scheduling on serves Contexa's beans too, on its own pool, which Boot sizes at one thread.
     */
    @Bean(name = TASK_SCHEDULER, defaultCandidate = false)
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static ThreadPoolTaskScheduler contexaTaskScheduler(Environment environment) {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(Math.max(CONTEXA_SCHEDULER_THREADS, environment.getProperty("spring.task.scheduling.pool.size", Integer.class, 1)));
        scheduler.setThreadNamePrefix("contexa-scheduling-");
        scheduler.setRemoveOnCancelPolicy(true);
        scheduler.setDaemon(true);
        return scheduler;
    }

    @Bean(name = "contexaScheduledAnnotationProcessor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static ContexaScheduledAnnotationBeanPostProcessor contexaScheduledAnnotationProcessor(
            @Qualifier(TASK_SCHEDULER) ThreadPoolTaskScheduler contexaTaskScheduler) {
        return new ContexaScheduledAnnotationBeanPostProcessor(contexaTaskScheduler);
    }

    /**
     * Always there: whether it serves Contexa's beans is decided when a bean is processed (the application's support may look at a marker of
     * its own instead of {@code @Async}, in which case this one must serve them).
     */
    @Bean(name = "contexaAsyncAnnotationProcessor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static ContexaAsyncAnnotationBeanPostProcessor contexaAsyncAnnotationProcessor(BeanFactory beanFactory) {
        ContexaAsyncAnnotationBeanPostProcessor processor = new ContexaAsyncAnnotationBeanPostProcessor();
        processor.configure(() -> beanFactory.getBean("contexaTaskExecutor", Executor.class), null);
        return processor;
    }

    /**
     * The cache manager of Contexa's own cached methods. Every cache annotation of Contexa names it ({@code @CacheConfig}), so that
     * Contexa's caches never share a store with the application's caches of the same name, whoever applies the annotations. It is not a
     * candidate for injection by type: an application that has no cache manager of its own keeps having none. The processor
     * below needs it before every post processor is there, which is what the infrastructure role says.
     */
    @Bean(name = "contexaCacheManager", autowireCandidate = false)
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static CacheManager contexaCacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager();
        manager.setCaffeine(ContexaCaffeine.newBuilder()
                .maximumSize(500)
                .expireAfterWrite(Duration.ofMinutes(5)));
        return manager;
    }

    @Bean(name = "contexaCacheAnnotationProcessor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static ContexaCacheAnnotationBeanPostProcessor contexaCacheAnnotationProcessor(BeanFactory beanFactory) {
        return new ContexaCacheAnnotationBeanPostProcessor(beanFactory.getBean("contexaCacheManager", CacheManager.class));
    }
}
