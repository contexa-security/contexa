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
package io.contexa.contexacore.std.streaming;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.infra.ContexaReactorResources;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProperties;
import org.junit.jupiter.api.Test;
import reactor.core.Disposable;
import reactor.core.Scannable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The five minutes a stream of the standard service may last are measured on Contexa's timer: while a stream runs, its time limit
 * is a task waiting there. Given no scheduler, {@code timeout} would wait on Reactor's {@code parallel} scheduler, which the whole
 * JVM shares, for every stream.
 */
class DefaultStandardStreamingServiceTimerTest {

    @Test
    @SuppressWarnings("unchecked")
    void theLimitOfAStreamOfThePipelineWaitsOnContexasTimer() {
        PipelineOrchestrator pipeline = mock(PipelineOrchestrator.class);
        when(pipeline.executeStream(any(AIRequest.class))).thenReturn(Flux.never());
        DefaultStandardStreamingService service = new DefaultStandardStreamingService(new StreamingProperties(), new ObjectMapper());

        int before = pendingOnContexasTimer();
        Disposable stream = service.stream(mock(AIRequest.class), pipeline).subscribe();
        try {
            assertThat(pendingOnContexasTimer()).isEqualTo(before + 1);
        } finally {
            stream.dispose();
        }
        assertThat(pendingOnContexasTimer()).isEqualTo(before);
    }

    @Test
    @SuppressWarnings("unchecked")
    void theLimitOfAStreamOfAStrategyWaitsOnContexasTimer() {
        AICoreOperations<?> operations = mock(AICoreOperations.class);
        when(operations.processStream(any(AIRequest.class))).thenReturn(Flux.never());
        DefaultStandardStreamingService service = new DefaultStandardStreamingService(new StreamingProperties(), new ObjectMapper());

        int before = pendingOnContexasTimer();
        Disposable stream = service.stream(mock(AIRequest.class), (AICoreOperations) operations).subscribe();
        try {
            assertThat(pendingOnContexasTimer()).isEqualTo(before + 1);
        } finally {
            stream.dispose();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void aStreamThatEndsGivesItsChunksAndItsEndAsBefore() {
        PipelineOrchestrator pipeline = mock(PipelineOrchestrator.class);
        when(pipeline.executeStream(any(AIRequest.class))).thenReturn(Flux.just("the answer is ready!" + System.lineSeparator()));
        DefaultStandardStreamingService service = new DefaultStandardStreamingService(new StreamingProperties(), new ObjectMapper());
        AIRequest<DomainContext> request = mock(AIRequest.class);

        List<String> events = service.stream(request, pipeline).map(event -> String.valueOf(event.data()))
                .collectList().block(Duration.ofSeconds(10));

        assertThat(events).isNotEmpty();
        assertThat(String.join("", events)).contains("the answer is ready!");
        assertThat(events.get(events.size() - 1)).contains("[DONE]");
    }

    /**
     * The tasks the timer's workers hold: those waiting for their time and the one running. A worker whose thread has just been
     * started counts as running until the thread is in, so every worker is started and idle first.
     */
    private static int pendingOnContexasTimer() {
        for (int i = 0; i < 4; i++) {
            Mono.delay(Duration.ofMillis(1), ContexaReactorResources.timer()).block(Duration.ofSeconds(5));
        }
        try {
            Thread.sleep(50L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return Scannable.from(ContexaReactorResources.timer()).inners()
                .mapToInt(worker -> worker.scanOrDefault(Scannable.Attr.BUFFERED, 0)).sum();
    }
}
