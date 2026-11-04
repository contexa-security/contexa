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
package io.contexa.contexacore.infra;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ContexaBackgroundExecutionTest {

    @Test
    void reactiveWorkRunsOnContexasDaemonThreadsNotTheJvmsSharedOnes() {
        Thread thread = Mono.fromCallable(Thread::currentThread)
                .subscribeOn(ContexaBackgroundExecution.scheduler())
                .block(Duration.ofSeconds(10));

        assertThat(thread).isNotNull();
        assertThat(thread.getName()).startsWith("contexa-blocking");
        assertThat(thread.isDaemon()).isTrue();
    }

    @Test
    void futureWorkRunsOnContexasDaemonThreadsNotTheCommonPool() throws Exception {
        Thread thread = CompletableFuture.supplyAsync(Thread::currentThread, ContexaBackgroundExecution.executor())
                .get(10, TimeUnit.SECONDS);

        assertThat(thread.getName()).startsWith("contexa-background-");
        assertThat(thread.isDaemon()).isTrue();
    }
}
