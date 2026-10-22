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
package io.contexa.contexacore.std.llm.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.OpenAiApi;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A chat model of another model id made from a configured one (docs/showcase/판정층-수정계획.md E-7): the same provider,
 * client and options, only the model differs; a provider whose chat model cannot be copied has none.
 */
class ChatModelVariantsTest {

    private static OpenAiChatModel openAi(String model) {
        return OpenAiChatModel.builder()
                .openAiApi(OpenAiApi.builder().apiKey("test").build())
                .defaultOptions(OpenAiChatOptions.builder().model(model).temperature(0.2).build())
                .build();
    }

    @Test
    @DisplayName("an OpenAI chat model gives one of another model id with the same options, and stays as it is")
    void anOpenAiModelGivesAVariant() {
        OpenAiChatModel layer1 = openAi("gpt-6-luna");

        ChatModel layer2 = ChatModelVariants.withModel(layer1, "gpt-6.1-sol").orElseThrow();

        assertThat(layer2).isInstanceOf(OpenAiChatModel.class).isNotSameAs(layer1);
        OpenAiChatOptions options = (OpenAiChatOptions) layer2.getDefaultOptions();
        assertThat(options.getModel()).isEqualTo("gpt-6.1-sol");
        assertThat(options.getTemperature()).isEqualTo(0.2);
        assertThat(((OpenAiChatOptions) layer1.getDefaultOptions()).getModel()).isEqualTo("gpt-6-luna");
    }

    @Test
    @DisplayName("a chat model that cannot be copied (Anthropic has no mutate) gives none")
    void aModelWithoutMutateGivesNone() {
        AnthropicChatModel anthropic = AnthropicChatModel.builder()
                .anthropicApi(AnthropicApi.builder().apiKey("test").build())
                .defaultOptions(AnthropicChatOptions.builder().model("claude-haiku-5-5").build())
                .build();

        assertThat(ChatModelVariants.withModel(anthropic, "claude-opus-5-5")).isEmpty();
    }

    @Test
    @DisplayName("no base model or no model id gives none")
    void nothingToCopyGivesNone() {
        assertThat(ChatModelVariants.withModel(null, "gpt-6.1-sol")).isEmpty();
        assertThat(ChatModelVariants.withModel(openAi("gpt-6-luna"), " ")).isEmpty();
    }
}
