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

import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.FailureAnalyzer;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/**
 * org.redisson:redisson, which {@code contexa.infrastructure.mode=distributed} needs, brings a JCache provider, and
 * Spring Boot takes a JCache provider on the class path for the application's cache. An application that makes its
 * caches through JCache then reaches a provider without a configuration and does not start, with nothing that says why.
 * Contexa does not change the application's cache behind its back: the failed start names the cause and what to set.
 */
class RedissonJCacheFailureAnalyzer implements FailureAnalyzer {

    private static final String REDISSON_JCACHE = "org.redisson.jcache.";
    private static final String NO_DEFAULT_CONFIGURATION = "Default configuration hasn't been specified!";

    private static final String DESCRIPTION = "The application's cache went to the JCache provider of org.redisson:redisson, "
            + "which contexa.infrastructure.mode=distributed needs on the class path. That provider has no configuration, "
            + "so the cache could not be made and the application did not start.";

    private static final String ACTION = "Name the application's cache so that it does not go to JCache, for example "
            + "spring.cache.type=caffeine. An application that means to use Redisson's JCache gives it its configuration "
            + "with spring.cache.jcache.config.";

    @Override
    public FailureAnalysis analyze(Throwable failure) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable cause = failure; cause != null && seen.add(cause); cause = cause.getCause()) {
            if (isRedissonWithoutConfiguration(cause)) {
                return new FailureAnalysis(DESCRIPTION, ACTION, cause);
            }
        }
        return null;
    }

    private static boolean isRedissonWithoutConfiguration(Throwable failure) {
        StackTraceElement[] stack = failure.getStackTrace();
        return NO_DEFAULT_CONFIGURATION.equals(failure.getMessage()) && stack.length > 0
                && stack[0].getClassName().startsWith(REDISSON_JCACHE);
    }
}
