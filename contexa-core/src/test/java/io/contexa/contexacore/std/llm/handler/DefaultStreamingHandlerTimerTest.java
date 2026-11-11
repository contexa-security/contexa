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
package io.contexa.contexacore.std.llm.handler;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The time limits and the timed buffers of a stream run on Contexa's own timer. Reactor runs a {@code timeout(Duration)} and a
 * {@code buffer(Duration)} that are given no scheduler on its {@code parallel} scheduler, which belongs to the whole JVM: the
 * application's own reactive code waits on the same threads. The model below takes its time on a scheduler of the test, so the only
 * timers of a stream are the handler's.
 */
class DefaultStreamingHandlerTimerTest {

    private static final Scheduler MODEL = Schedulers.newSingle("test-model", true);

    @AfterAll
    static void stopTheModel() {
        MODEL.dispose();
    }

    @Test
    void aStreamThatGetsNoAnswerInItsTimeEndsOnContexasTimer() {
        DefaultStreamingHandler handler = new DefaultStreamingHandler(new TieredLLMProperties(), new JsonStreamingProcessor());
        ChatModel silent = model(Flux.never());
        ExecutionContext context = ExecutionContext.builder().prompt(new Prompt("decide")).timeoutMs(150).build();

        String endedOn = handler.handleStreaming(ChatClient.builder(silent).build(), context, silent)
                .map(chunk -> "chunk")
                .onErrorResume(error -> Flux.just(Thread.currentThread().getName()))
                .blockLast(Duration.ofSeconds(10));

        assertThat(endedOn).startsWith("contexa-timer-");
    }

    @Test
    void aFirstTierStreamEndsWithItsTimeoutAnswerOnContexasTimer() {
        TieredLLMProperties properties = new TieredLLMProperties();
        properties.getTiered().getLayer1().setTimeoutMs(150);
        DefaultStreamingHandler handler = new DefaultStreamingHandler(properties, new JsonStreamingProcessor());
        ChatModel silent = model(Flux.never());
        ExecutionContext context = ExecutionContext.builder().prompt(new Prompt("decide")).tier(1).build();
        String[] endedOn = new String[1];

        List<String> answer = handler.handleStreaming(ChatClient.builder(silent).build(), context, silent)
                .doOnComplete(() -> endedOn[0] = Thread.currentThread().getName())
                .collectList()
                .block(Duration.ofSeconds(10));

        // what the time limit gives is unchanged: the stream ends without an error, and the processor keeps the short
        // timeout answer to itself as it keeps any text of no more than a marker's length
        assertThat(answer).isEmpty();
        assertThat(endedOn[0]).startsWith("contexa-timer-");
    }

    @Test
    void aSecondTierStreamHandsOnItsBufferedChunksOnContexasTimer() {
        TieredLLMProperties properties = new TieredLLMProperties();
        // the buffer of the second tier is a sixth of its time limit: 100 ms
        properties.getTiered().getLayer2().setTimeoutMs(600);
        DefaultStreamingHandler handler = new DefaultStreamingHandler(properties, new JsonStreamingProcessor());
        // two chunks, then a pause the buffer outlasts, then the end
        ChatModel slow = model(Flux.concat(
                Mono.just(response("the first part of the answer ")),
                Mono.delay(Duration.ofMillis(20), MODEL).thenReturn(response("and the second part of it ")),
                Mono.delay(Duration.ofMillis(400), MODEL).then(Mono.empty())));
        ExecutionContext context = ExecutionContext.builder().prompt(new Prompt("decide")).tier(2).build();
        List<String> threads = new CopyOnWriteArrayList<>();

        List<String> chunks = handler.handleStreaming(ChatClient.builder(slow).build(), context, slow)
                .doOnNext(chunk -> threads.add(Thread.currentThread().getName()))
                .collectList()
                .block(Duration.ofSeconds(10));

        assertThat(String.join("", chunks)).contains("the first part of the answer").contains("the second part of it");
        assertThat(threads).isNotEmpty().anySatisfy(thread -> assertThat(thread).startsWith("contexa-timer-"));
        assertThat(threads).noneSatisfy(thread -> assertThat(thread).startsWith("parallel-"));
    }

    private static ChatModel model(Flux<ChatResponse> stream) {
        return new ChatModel() {
            @Override
            public ChatResponse call(Prompt prompt) {
                throw new UnsupportedOperationException("this model only streams");
            }

            @Override
            public Flux<ChatResponse> stream(Prompt prompt) {
                return stream;
            }

            @Override
            public ChatOptions getDefaultOptions() {
                return ChatOptions.builder().model("qwen3:8b").build();
            }
        };
    }

    private static ChatResponse response(String text) {
        return new ChatResponse(List.of(new Generation(new AssistantMessage(text))));
    }
}
