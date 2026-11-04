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
package io.contexa.contexacore.config;

import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spring calls {@code afterPropertiesSet()}, which initializes a {@code ThreadPoolTaskExecutor}, on every bean. A pool started by hand inside the bean method is
 * replaced by a second one then: its prestarted threads belong to nobody and are never stopped, and they are not daemons. Found by the hostile host: after a
 * failed start-up of the application the JVM did not end, 32 {@code LLM-Analysis} threads held it.
 */
class AsyncConfigLifecycleTest {

    private static final String POOL = "LLM-Analysis-";

    private static long poolThreads() {
        return Thread.getAllStackTraces().keySet().stream().filter(t -> t.isAlive() && t.getName().startsWith(POOL)).count();
    }

    private static boolean awaitPoolThreads(long expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
        while (poolThreads() != expected && System.nanoTime() < deadline) {
            Thread.sleep(25);
        }
        return poolThreads() == expected;
    }

    private static AnnotationConfigApplicationContext contextWith(int coreThreads, boolean prestart) {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getLlmExecutor().setCorePoolSize(coreThreads);
        properties.getLlmExecutor().setMaxPoolSize(coreThreads * 2);
        properties.getLlmExecutor().setPrestartCoreThreads(prestart);
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.registerBean(SecurityPlaneProperties.class, () -> properties);
        context.register(AsyncConfig.class);
        context.refresh();
        return context;
    }

    @Test
    @DisplayName("the prestarted threads are the threads of the pool the bean holds, and they stop with the context")
    void thePrestartedThreadsStopWithTheContext() throws Exception {
        long before = poolThreads();
        AnnotationConfigApplicationContext context = contextWith(3, true);
        try {
            ThreadPoolTaskExecutor executor = context.getBean("contexaLlmAnalysisExecutor", ThreadPoolTaskExecutor.class);
            assertThat(awaitPoolThreads(before + 3)).as("the core threads are started, once").isTrue();
            assertThat(executor.getThreadPoolExecutor().getPoolSize()).as("and they are the pool of the bean").isEqualTo(3);
        } finally {
            context.close();
        }
        assertThat(awaitPoolThreads(before)).as("no thread outlives the context").isTrue();
    }

    @Test
    @DisplayName("without the prestart the pool starts no thread until it is used")
    void withoutThePrestartNoThreadIsStarted() throws Exception {
        long before = poolThreads();
        AnnotationConfigApplicationContext context = contextWith(3, false);
        try {
            assertThat(poolThreads()).isEqualTo(before);
            assertThat(context.getBean("contexaLlmAnalysisExecutor", ThreadPoolTaskExecutor.class).getThreadPoolExecutor().getPoolSize()).isZero();
        } finally {
            context.close();
        }
    }
}
