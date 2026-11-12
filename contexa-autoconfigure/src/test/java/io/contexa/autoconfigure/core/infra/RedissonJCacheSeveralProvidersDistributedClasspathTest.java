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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.UnsatisfiedDependencyException;
import org.springframework.boot.diagnostics.FailureAnalysis;

import javax.cache.CacheManager;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-203: an application with a JCache provider of its own has two once org.redisson:redisson, which the distributed
 * mode needs, is on the class path. Spring Boot picks none of them, the application's javax.cache.CacheManager is not
 * made, and the start said "consider defining a bean" and nothing of why. The failed start names the cause and
 * spring.cache.jcache.provider. It runs on the class path with Redisson, where javax.cache is.
 */
class RedissonJCacheSeveralProvidersDistributedClasspathTest {

    private static RuntimeException asTheStartReportsIt(Class<?> missing) {
        return new UnsatisfiedDependencyException(null, "hibernatePropertiesCustomizer", "cacheManager",
                new NoSuchBeanDefinitionException(missing));
    }

    @Test
    @DisplayName("a missing javax.cache.CacheManager beside Redisson's provider names spring.cache.jcache.provider")
    void theFailureNamesTheProviderSetting() {
        FailureAnalysis analysis = new RedissonJCacheFailureAnalyzer(() -> true).analyze(asTheStartReportsIt(CacheManager.class));

        assertThat(analysis).isNotNull();
        assertThat(analysis.getDescription()).contains("more than one JCache provider").contains("org.redisson:redisson");
        assertThat(analysis.getAction()).contains("spring.cache.jcache.provider");
    }

    @Test
    @DisplayName("with one provider on the class path the missing bean is left to Spring Boot")
    void oneProviderIsLeftAlone() {
        assertThat(new RedissonJCacheFailureAnalyzer(() -> false).analyze(asTheStartReportsIt(CacheManager.class))).isNull();
    }

    @Test
    @DisplayName("another missing bean of the application is left alone")
    void anotherMissingBeanIsLeftAlone() {
        assertThat(new RedissonJCacheFailureAnalyzer(() -> true).analyze(asTheStartReportsIt(Runnable.class))).isNull();
    }

    @Test
    @DisplayName("this class path has Redisson's provider only, and the analyzer Spring Boot makes sees that")
    void theClassPathIsRead() {
        assertThat(new RedissonJCacheFailureAnalyzer().analyze(asTheStartReportsIt(CacheManager.class))).isNull();
    }
}
