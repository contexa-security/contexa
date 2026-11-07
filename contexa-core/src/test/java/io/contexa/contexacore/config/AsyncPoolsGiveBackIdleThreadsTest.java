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

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An application's threads are its own: a pool of Contexa's that has nothing to run gives its threads back. A
 * {@code ThreadPoolTaskExecutor} keeps its core threads for ever unless it is told to give them back.
 */
class AsyncPoolsGiveBackIdleThreadsTest {

    @Test
    @DisplayName("every pool of the async configuration gives back the threads it has no work for")
    void everyPoolGivesBackIdleThreads() {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.registerBean(SecurityPlaneProperties.class, SecurityPlaneProperties::new);
        context.register(AsyncConfig.class);
        context.refresh();
        try {
            Map<String, ThreadPoolTaskExecutor> pools = context.getBeansOfType(ThreadPoolTaskExecutor.class);

            assertThat(pools).hasSize(6);
            pools.forEach((name, pool) -> assertThat(pool.getThreadPoolExecutor().allowsCoreThreadTimeOut())
                    .as("the pool %s gives back its idle core threads", name).isTrue());
        }
        finally {
            context.close();
        }
    }
}
