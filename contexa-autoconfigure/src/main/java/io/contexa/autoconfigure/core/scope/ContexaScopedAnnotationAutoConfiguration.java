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

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.cache.config.CacheManagementConfigUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.config.TaskManagementConfigUtils;

import java.time.Duration;
import java.util.concurrent.Executor;

/**
 * Scheduling, asynchronous execution and caching for Contexa's own beans, and for them only.
 * <p>
 * Contexa used to switch these on for the whole application ({@code @EnableScheduling}, {@code @EnableAsync}, {@code @EnableCaching}), which
 * made the application's dormant {@code @Scheduled}, {@code @Async} and {@code @Cacheable} methods start to run, run on another thread, and
 * cache. Each support is now a post-processor that looks at Contexa's classes only. When the application turned the support on itself, its
 * own processor already handles Contexa's beans and Contexa adds nothing (the bean names Spring uses for its processors tell).
 */
@AutoConfiguration
public class ContexaScopedAnnotationAutoConfiguration {

    @Bean(name = "contexaScheduledAnnotationProcessor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    @ConditionalOnMissingBean(name = TaskManagementConfigUtils.SCHEDULED_ANNOTATION_PROCESSOR_BEAN_NAME)
    static ContexaScheduledAnnotationBeanPostProcessor contexaScheduledAnnotationProcessor(Environment environment) {
        return new ContexaScheduledAnnotationBeanPostProcessor(environment.getProperty("spring.task.scheduling.pool.size", Integer.class, 1));
    }

    @Bean(name = "contexaAsyncAnnotationProcessor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    @ConditionalOnMissingBean(name = TaskManagementConfigUtils.ASYNC_ANNOTATION_PROCESSOR_BEAN_NAME)
    static ContexaAsyncAnnotationBeanPostProcessor contexaAsyncAnnotationProcessor(BeanFactory beanFactory) {
        ContexaAsyncAnnotationBeanPostProcessor processor = new ContexaAsyncAnnotationBeanPostProcessor();
        processor.configure(() -> beanFactory.getBean("contexaTaskExecutor", Executor.class), null);
        return processor;
    }

    /**
     * The cache manager of Contexa's own cached methods. Every cache annotation of Contexa names it ({@code @CacheConfig}), so that
     * Contexa's caches never share a store with the application's caches of the same name, whoever applies the annotations. It is not a
     * candidate for injection by type: an application that has no cache manager of its own keeps having none.
     */
    @Bean(name = "contexaCacheManager", autowireCandidate = false)
    CacheManager contexaCacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager();
        manager.setCaffeine(Caffeine.newBuilder()
                .maximumSize(500)
                .expireAfterWrite(Duration.ofMinutes(5)));
        return manager;
    }

    @Bean(name = "contexaCacheAnnotationProcessor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    @ConditionalOnMissingBean(name = CacheManagementConfigUtils.CACHE_ADVISOR_BEAN_NAME)
    static ContexaCacheAnnotationBeanPostProcessor contexaCacheAnnotationProcessor(BeanFactory beanFactory) {
        return new ContexaCacheAnnotationBeanPostProcessor(beanFactory.getBean("contexaCacheManager", CacheManager.class));
    }
}
