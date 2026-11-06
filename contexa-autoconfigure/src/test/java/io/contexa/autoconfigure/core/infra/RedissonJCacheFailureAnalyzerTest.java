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
import org.springframework.beans.BeanInstantiationException;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.FailureAnalyzer;
import org.springframework.core.io.support.SpringFactoriesLoader;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-71: org.redisson:redisson, which the distributed mode needs, brings a JCache provider. An application whose cache
 * goes through JCache then starts on Redisson's provider and dies without a word of why. Contexa changes no setting of
 * the application: the failed start says what happened and what to set.
 */
class RedissonJCacheFailureAnalyzerTest {

    private static final String MESSAGE = "Default configuration hasn't been specified!";

    private final RedissonJCacheFailureAnalyzer analyzer = new RedissonJCacheFailureAnalyzer();

    private static IllegalStateException thrownBy(String className, String message) {
        IllegalStateException failure = new IllegalStateException(message);
        failure.setStackTrace(new StackTraceElement[]{new StackTraceElement(className, "createCache", "Source.java", 112)});
        return failure;
    }

    private static RuntimeException asTheStartReportsIt(Throwable failure) {
        return new BeanCreationException("cacheManager", "Error creating bean with name 'cacheManager'",
                new BeanInstantiationException(Object.class, "Factory method 'jCacheCacheManager' threw exception", failure));
    }

    @Test
    @DisplayName("the failed start names the provider and spring.cache.type=caffeine")
    void theFailureSaysWhatHappenedAndWhatToSet() {
        FailureAnalysis analysis = analyzer.analyze(asTheStartReportsIt(thrownBy("org.redisson.jcache.JCacheManager", MESSAGE)));

        assertThat(analysis).isNotNull();
        assertThat(analysis.getDescription()).contains("org.redisson:redisson").contains("JCache");
        assertThat(analysis.getAction()).contains("spring.cache.type=caffeine");
    }

    @Test
    @DisplayName("an IllegalStateException of the application is left alone")
    void anotherFailureIsLeftAlone() {
        assertThat(analyzer.analyze(asTheStartReportsIt(new IllegalStateException("the shop has no currency")))).isNull();
    }

    @Test
    @DisplayName("the same words from another library are left alone")
    void theSameWordsElsewhereAreLeftAlone() {
        assertThat(analyzer.analyze(asTheStartReportsIt(thrownBy("com.shop.cache.ShopCacheManager", MESSAGE)))).isNull();
    }

    @Test
    @DisplayName("another failure inside Redisson's provider is left alone")
    void anotherRedissonFailureIsLeftAlone() {
        assertThat(analyzer.analyze(asTheStartReportsIt(thrownBy("org.redisson.jcache.JCacheManager", "Redis is down")))).isNull();
    }

    @Test
    @DisplayName("a failure with a cycle in its causes ends")
    void aCycleInTheCausesEnds() {
        IllegalStateException first = new IllegalStateException("first");
        IllegalStateException second = new IllegalStateException("second", first);
        first.initCause(second);

        assertThat(analyzer.analyze(first)).isNull();
    }

    @Test
    @DisplayName("Spring Boot finds the analyzer in a start of the application")
    void theAnalyzerIsRegistered() {
        // Spring Boot's own analyzers take constructor arguments only its start gives; they are not what this asks about.
        assertThat(SpringFactoriesLoader.forDefaultResourceLocation(getClass().getClassLoader())
                .load(FailureAnalyzer.class, SpringFactoriesLoader.FailureHandler.handleMessage((message, failure) -> {
                })))
                .hasAtLeastOneElementOfType(RedissonJCacheFailureAnalyzer.class);
    }
}
