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

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.FailureAnalyzer;
import org.springframework.core.annotation.Order;
import org.springframework.util.ClassUtils;

import java.io.IOException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.function.BooleanSupplier;

/**
 * org.redisson:redisson, which {@code contexa.infrastructure.mode=distributed} needs, brings a JCache provider, and
 * Spring Boot takes a JCache provider on the class path for the application's cache. An application that makes its
 * caches through JCache then reaches a provider without a configuration and does not start, with nothing that says why.
 * An application with a JCache provider of its own (Ehcache, for instance) then has two: Spring Boot picks none of
 * them, the application's javax.cache.CacheManager is not made, and the start names a missing bean and nothing else.
 * Contexa does not change the application's cache behind its back: the failed start names the cause and what to set.
 */
// Ahead of Spring Boot's analyzer of a missing bean, which would answer the second case with "consider defining a bean".
@Order(0)
class RedissonJCacheFailureAnalyzer implements FailureAnalyzer {

    private static final String REDISSON_JCACHE = "org.redisson.jcache.";
    private static final String REDISSON_PROVIDER = REDISSON_JCACHE + "JCachingProvider";
    private static final String NO_DEFAULT_CONFIGURATION = "Default configuration hasn't been specified!";
    private static final String JCACHE_MANAGER = "javax.cache.CacheManager";
    private static final String PROVIDER_SERVICE = "META-INF/services/javax.cache.spi.CachingProvider";

    private static final String DESCRIPTION = "The application's cache went to the JCache provider of org.redisson:redisson, "
            + "which contexa.infrastructure.mode=distributed needs on the class path. That provider has no configuration, "
            + "so the cache could not be made and the application did not start.";

    private static final String ACTION = "Name the application's cache so that it does not go to JCache, for example "
            + "spring.cache.type=caffeine. An application that means to use Redisson's JCache gives it its configuration "
            + "with spring.cache.jcache.config.";

    private static final String SEVERAL_PROVIDERS_DESCRIPTION = "The class path has more than one JCache provider: the "
            + "application's own and that of org.redisson:redisson, which contexa.infrastructure.mode=distributed needs. "
            + "Spring Boot picks none when there is more than one, so the application's javax.cache.CacheManager was not "
            + "made and the application did not start.";

    private static final String SEVERAL_PROVIDERS_ACTION = "Name the application's provider with spring.cache.jcache.provider, "
            + "for example spring.cache.jcache.provider=org.ehcache.jsr107.EhcacheCachingProvider.";

    private final BooleanSupplier redissonBesideAnotherProvider;

    RedissonJCacheFailureAnalyzer() {
        this(RedissonJCacheFailureAnalyzer::redissonBesideAnotherProvider);
    }

    RedissonJCacheFailureAnalyzer(BooleanSupplier redissonBesideAnotherProvider) {
        this.redissonBesideAnotherProvider = redissonBesideAnotherProvider;
    }

    @Override
    public FailureAnalysis analyze(Throwable failure) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable cause = failure; cause != null && seen.add(cause); cause = cause.getCause()) {
            if (isRedissonWithoutConfiguration(cause)) {
                return new FailureAnalysis(DESCRIPTION, ACTION, cause);
            }
            if (isJCacheManagerMissing(cause) && redissonBesideAnotherProvider.getAsBoolean()) {
                return new FailureAnalysis(SEVERAL_PROVIDERS_DESCRIPTION, SEVERAL_PROVIDERS_ACTION, cause);
            }
        }
        return null;
    }

    private static boolean isRedissonWithoutConfiguration(Throwable failure) {
        StackTraceElement[] stack = failure.getStackTrace();
        return NO_DEFAULT_CONFIGURATION.equals(failure.getMessage()) && stack.length > 0
                && stack[0].getClassName().startsWith(REDISSON_JCACHE);
    }

    private static boolean isJCacheManagerMissing(Throwable failure) {
        return failure instanceof NoSuchBeanDefinitionException missing && missing.getBeanType() != null
                && JCACHE_MANAGER.equals(missing.getBeanType().getName());
    }

    private static boolean redissonBesideAnotherProvider() {
        ClassLoader loader = RedissonJCacheFailureAnalyzer.class.getClassLoader();
        if (!ClassUtils.isPresent(REDISSON_PROVIDER, loader)) {
            return false;
        }
        try {
            return Collections.list(loader.getResources(PROVIDER_SERVICE)).size() > 1;
        } catch (IOException e) {
            // The class path could not be read: the start keeps the failure it had, and Spring Boot's own analysis.
            return false;
        }
    }
}
