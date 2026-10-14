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
package io.contexa.contexacore.std.llm.client;

import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisor;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.client.advisor.api.StreamAdvisor;
import org.springframework.ai.chat.client.advisor.api.StreamAdvisorChain;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.core.Ordered;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Leaves out the thinking a provider returns as generations before its answer (Spring AI's Anthropic thinking blocks
 * carry their signature, redacted ones their data), so what reads the first generation of a response (entity
 * conversion, output validation, streamed content) reads the answer. It sits next to the model call, inside every
 * other advisor. A response of thinking alone (the output limit stopped it before the answer) becomes one empty answer
 * that keeps the thinking's finish reason.
 */
public final class ThinkingGenerationAdvisor implements CallAdvisor, StreamAdvisor {

    /** The metadata key of a thinking generation (its signature) and of a redacted one (its data). */
    private static final String THINKING_SIGNATURE = "signature";
    private static final String REDACTED_THINKING_DATA = "data";

    public static final ThinkingGenerationAdvisor INSTANCE = new ThinkingGenerationAdvisor();

    private ThinkingGenerationAdvisor() {
    }

    @Override
    public ChatClientResponse adviseCall(ChatClientRequest request, CallAdvisorChain chain) {
        return withoutThinking(chain.nextCall(request));
    }

    @Override
    public Flux<ChatClientResponse> adviseStream(ChatClientRequest request, StreamAdvisorChain chain) {
        return chain.nextStream(request).map(ThinkingGenerationAdvisor::withoutThinking);
    }

    /** Whether a generation's message is a provider's thinking, by the marks Spring AI puts on it. */
    public static boolean isThinking(AssistantMessage message) {
        Map<String, Object> metadata = message.getMetadata();
        return metadata != null
                && (metadata.containsKey(THINKING_SIGNATURE) || metadata.containsKey(REDACTED_THINKING_DATA));
    }

    static ChatClientResponse withoutThinking(ChatClientResponse response) {
        if (response == null || response.chatResponse() == null) {
            return response;
        }
        List<Generation> generations = response.chatResponse().getResults();
        List<Generation> answers = new ArrayList<>();
        Generation firstThinking = null;
        for (Generation generation : generations) {
            if (generation != null && generation.getOutput() != null && isThinking(generation.getOutput())) {
                firstThinking = firstThinking == null ? generation : firstThinking;
                continue;
            }
            answers.add(generation);
        }
        if (firstThinking == null) {
            return response;
        }
        if (answers.isEmpty()) {
            answers.add(new Generation(new AssistantMessage(""), firstThinking.getMetadata()));
        }
        ChatResponse chatResponse = ChatResponse.builder().from(response.chatResponse()).generations(answers).build();
        return response.mutate().chatResponse(chatResponse).build();
    }

    @Override
    public String getName() {
        return "ThinkingGenerationAdvisor";
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE - 1;
    }
}
