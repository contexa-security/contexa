/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 */
package io.contexa.autoconfigure.core.llm;

import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.ProviderAwareChatOptionsFactory;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

class OpenAiChatModelOptionsAutoConfigurationTest {

    @Test
    void gpt5NanoUsesCompletionTokenAndDefaultSamplingOptionsWithoutUserConfiguration() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.ai.openai.chat.options.model", "gpt-5-nano");
        OpenAiChatModelOptionsAutoConfiguration
                .providerAwareChatOptionsEnvironmentBridge(environment)
                .postProcessBeanFactory(new DefaultListableBeanFactory());

        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(128);
        context.setTemperature(0.2d);
        context.setTopP(0.8d);
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
        assertThat(openAiOptions.getMaxCompletionTokens()).isEqualTo(128);
        assertThat(openAiOptions.getTemperature()).isNull();
        assertThat(openAiOptions.getTopP()).isNull();
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
