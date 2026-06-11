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

import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.openai.OpenAiChatOptions;

import static org.assertj.core.api.Assertions.assertThat;

class ProviderAwareChatOptionsFactoryTest {

    @Test
    void buildRuntimeOptionsShouldUseMaxCompletionTokensForGpt5OpenAiModels() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(96);
        context.setTemperature(0.0d);
        context.addMetadata("selectedModelProvider", "openai");

        ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(
                context,
                new StubChatModel(OpenAiChatOptions.builder().model("gpt-5-nano").build()));

        assertThat(options).isInstanceOf(OpenAiChatOptions.class);
        OpenAiChatOptions openAiOptions = (OpenAiChatOptions) options;
        assertThat(openAiOptions.getModel()).isEqualTo("gpt-5-nano");
        assertThat(openAiOptions.getMaxTokens()).isNull();
        assertThat(openAiOptions.getMaxCompletionTokens()).isEqualTo(96);
        assertThat(openAiOptions.getTemperature()).isEqualTo(0.0d);
    }

    @Test
    void normalizeExplicitOptionsShouldMoveOpenAiGpt5MaxTokensToMaxCompletionTokens() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        ChatOptions explicitOptions = OpenAiChatOptions.builder()
                .model("gpt-5-nano")
                .maxTokens(128)
                .build();

        ChatOptions normalized = ProviderAwareChatOptionsFactory.normalizeExplicitOptions(
                explicitOptions,
                context,
                new StubChatModel(explicitOptions));

        assertThat(normalized).isInstanceOf(OpenAiChatOptions.class);
        OpenAiChatOptions openAiOptions = (OpenAiChatOptions) normalized;
        assertThat(openAiOptions.getMaxTokens()).isNull();
        assertThat(openAiOptions.getMaxCompletionTokens()).isEqualTo(128);
    }

    @Test
    void normalizeExplicitOptionsShouldKeepLegacyOpenAiMaxTokens() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        ChatOptions explicitOptions = OpenAiChatOptions.builder()
                .model("gpt-4o-mini")
                .maxTokens(128)
                .build();

        ChatOptions normalized = ProviderAwareChatOptionsFactory.normalizeExplicitOptions(
                explicitOptions,
                context,
                new StubChatModel(explicitOptions));

        assertThat(normalized).isSameAs(explicitOptions);
        OpenAiChatOptions openAiOptions = (OpenAiChatOptions) normalized;
        assertThat(openAiOptions.getMaxTokens()).isEqualTo(128);
        assertThat(openAiOptions.getMaxCompletionTokens()).isNull();
    }

    @Test
    void buildRuntimeOptionsShouldConvertDefaultOpenAiGpt5MaxTokensEvenWithoutRuntimeMaxTokens() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.addMetadata("selectedModelProvider", "openai");

        ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(
                context,
                new StubChatModel(OpenAiChatOptions.builder()
                        .model("gpt-5-nano")
                        .maxTokens(256)
                        .build()));

        assertThat(options).isInstanceOf(OpenAiChatOptions.class);
        OpenAiChatOptions openAiOptions = (OpenAiChatOptions) options;
        assertThat(openAiOptions.getMaxTokens()).isNull();
        assertThat(openAiOptions.getMaxCompletionTokens()).isEqualTo(256);
    }

    private record StubChatModel(ChatOptions defaultOptions) implements ChatModel {

        @Override
        public ChatResponse call(Prompt prompt) {
            throw new UnsupportedOperationException("not used");
        }

        @Override
        public ChatOptions getDefaultOptions() {
            return defaultOptions;
        }
    }
}
