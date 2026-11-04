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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.cache.CacheAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An application that turns caching on and defines no cache manager gets Spring Boot's. Contexa's cache manager is hidden from
 * autowiring and used by name, but it is a bean of the shared type: the question is whether Spring Boot still creates the application's
 * manager, and whether the application's {@code @Cacheable} then reaches it and not Contexa's.
 */
class ContexaCacheManagerHostCoexistenceTest {

    @Configuration(proxyBeanMethods = false)
    @EnableCaching
    static class TheApplication {

        @Bean
        Orders orders() {
            return new Orders();
        }
    }

    static class Orders {

        private final AtomicInteger loads = new AtomicInteger();

        public int loads() {
            return loads.get();
        }

        @Cacheable("orders")
        public int load(String id) {
            return loads.incrementAndGet();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ContexasOwnManager {

        @Bean(name = "contexaCacheManager", autowireCandidate = false)
        CaffeineCacheManager contexaCacheManager() {
            return new CaffeineCacheManager();
        }
    }

    private final ApplicationContextRunner contexts = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CacheAutoConfiguration.class))
            .withUserConfiguration(TheApplication.class);

    @Test
    @DisplayName("control: the application alone gets Spring Boot's cache manager and its cache is used")
    void theApplicationAloneUsesBootsManager() {
        contexts.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBeansOfType(CacheManager.class)).containsOnlyKeys("cacheManager");
            Orders orders = context.getBean(Orders.class);
            orders.load("1");
            orders.load("1");
            assertThat(orders.loads()).as("the second call is served from the cache").isEqualTo(1);
        });
    }

    @Test
    @DisplayName("with Contexa's hidden cache manager the application still gets Spring Boot's, and its cache is the one used")
    void theApplicationStillGetsBootsManager() {
        contexts.withUserConfiguration(ContexasOwnManager.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBeansOfType(CacheManager.class)).containsKeys("cacheManager", "contexaCacheManager");
            Orders orders = context.getBean(Orders.class);
            orders.load("1");
            assertThat(context.getBean("cacheManager", CacheManager.class).getCache("orders").get("1"))
                    .as("the application's entry is in Spring Boot's manager").isNotNull();
            assertThat(context.getBean("contexaCacheManager", CacheManager.class).getCacheNames())
                    .as("and none in Contexa's").doesNotContain("orders");
        });
    }
}
