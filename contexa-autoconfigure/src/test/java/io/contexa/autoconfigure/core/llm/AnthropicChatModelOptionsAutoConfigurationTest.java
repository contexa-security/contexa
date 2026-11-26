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

import io.contexa.contexacore.std.llm.client.ProviderAwareChatOptionsFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.anthropic.api.AnthropicCacheOptions;
import org.springframework.ai.anthropic.api.AnthropicCacheStrategy;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.env.MockEnvironment;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Claude Haiku 5.5: the defaults of the Anthropic chat model Contexa calls are made fit for the Claude model it runs.
 * Spring AI sets a default temperature of 0.8, which the newest Claude models refuse with a 400 error; and Anthropic
 * caches only the prompt a request marks, so the system prompt is marked unless a cache strategy is configured. R-9: this
 * is done on Contexa's own instance of the model; the model it is made from keeps its options.
 */
class AnthropicChatModelOptionsAutoConfigurationTest {

    @Test
    @DisplayName("기본 샘플링만 받는 Claude 모델의 Contexa 인스턴스는 Spring AI 온도를 빼고 시스템 프롬프트를 캐시하며 원본은 그대로다")
    void aClaudeModelThatTakesOnlyTheDefaultSamplingLosesTheSpringAiTemperatureAndCachesItsSystemPrompt() {
        AnthropicChatModel model = model(AnthropicChatOptions.builder().model("claude-haiku-5-5").temperature(0.8d)
                .topK(5).maxTokens(500).build());

        ChatModel contexas = copies(new MockEnvironment()).of(model);

        AnthropicChatOptions defaults = (AnthropicChatOptions) contexas.getDefaultOptions();
        assertThat(defaults.getTemperature()).isNull();
        assertThat(defaults.getTopK()).isNull();
        assertThat(defaults.getMaxTokens()).isEqualTo(500);
        assertThat(defaults.getCacheOptions().getStrategy()).isEqualTo(AnthropicCacheStrategy.SYSTEM_ONLY);
        AnthropicChatOptions original = (AnthropicChatOptions) model.getDefaultOptions();
        assertThat(original.getTemperature()).isEqualTo(0.8d);
        assertThat(original.getTopK()).isEqualTo(5);
    }

    @Test
    @DisplayName("같은 모델의 Contexa 인스턴스는 한 번만 만들어진다")
    void aModelsInstanceIsMadeOnce() {
        AnthropicChatModel model = model(AnthropicChatOptions.builder().model("claude-haiku-5-5").maxTokens(500).build());
        ContexaChatModelCopies copies = copies(new MockEnvironment());

        assertThat(copies.of(model)).isSameAs(copies.of(model)).isNotSameAs(model);
    }

    @Test
    @DisplayName("이전 Claude 모델은 샘플링을 유지하고 설정된 캐시 전략도 유지한다")
    void anOlderClaudeModelKeepsItsSamplingAndAConfiguredCacheStrategyIsKept() {
        AnthropicChatModel model = model(AnthropicChatOptions.builder().model("claude-haiku-4-5").temperature(0.8d)
                .cacheOptions(AnthropicCacheOptions.builder().strategy(AnthropicCacheStrategy.TOOLS_ONLY).build())
                .build());

        AnthropicChatOptions defaults = (AnthropicChatOptions) copies(new MockEnvironment()).of(model).getDefaultOptions();

        assertThat(defaults.getTemperature()).isEqualTo(0.8d);
        assertThat(defaults.getCacheOptions().getStrategy()).isEqualTo(AnthropicCacheStrategy.TOOLS_ONLY);
    }

    @Test
    @DisplayName("시스템 프롬프트 캐시는 설정으로 끌 수 있다")
    void theSystemPromptCacheCanBeTurnedOff() {
        AnthropicChatModel model = model(AnthropicChatOptions.builder().model("claude-haiku-5-5").build());

        ChatModel contexas = copies(new MockEnvironment()
                .withProperty("contexa.llm.model-capabilities.anthropic.system-prompt-cache", "false")).of(model);

        assertThat(((AnthropicChatOptions) contexas.getDefaultOptions()).getCacheOptions().getStrategy())
                .isEqualTo(AnthropicCacheStrategy.NONE);
    }

    @Test
    void theConfiguredPatternsDecideWhichClaudeModelsTakeOnlyTheDefaultSampling() {
        try {
            AnthropicChatModelOptionsAutoConfiguration.CapabilitiesBridge bridge =
                    AnthropicChatModelOptionsAutoConfiguration.anthropicModelCapabilitiesEnvironmentBridge();
            bridge.setEnvironment(new MockEnvironment()
                    .withProperty("contexa.llm.model-capabilities.anthropic.default-sampling-only-patterns",
                            "claude-haiku-4-5"));
            bridge.postProcessBeanFactory(new DefaultListableBeanFactory());

            assertThat(ProviderAwareChatOptionsFactory.anthropicUsesDefaultSamplingOnly("claude-haiku-4-5")).isTrue();
            assertThat(ProviderAwareChatOptionsFactory.anthropicUsesDefaultSamplingOnly("claude-haiku-5-5")).isFalse();
        }
        finally {
            ProviderAwareChatOptionsFactory.configureAnthropicModelCapabilities(
                    ProviderAwareChatOptionsFactory.ANTHROPIC_DEFAULT_SAMPLING_ONLY_PATTERNS);
        }
    }

    /**
     * Design 4.5-A: from Anthropic API version 2026-10-21 every model refuses every temperature, top-p and top-k value,
     * default values included (Claude API migration guide), so no Claude model's defaults keep one.
     */
    @Test
    void anApiVersionThatRefusesEverySamplingValueTakesSamplingOutOfEveryClaudeModel() {
        AnthropicChatModelOptionsAutoConfiguration.CapabilitiesBridge bridge =
                AnthropicChatModelOptionsAutoConfiguration.anthropicModelCapabilitiesEnvironmentBridge();
        try {
            bridge.setEnvironment(new MockEnvironment().withProperty("spring.ai.anthropic.version", "2026-10-21"));
            bridge.postProcessBeanFactory(new DefaultListableBeanFactory());
            AnthropicChatModel model = model(AnthropicChatOptions.builder().model("claude-haiku-4-5").temperature(0.8d)
                    .topP(0.9d).build());

            AnthropicChatOptions defaults =
                    (AnthropicChatOptions) copies(new MockEnvironment()).of(model).getDefaultOptions();
            assertThat(defaults.getTemperature()).isNull();
            assertThat(defaults.getTopP()).isNull();
        }
        finally {
            bridge.setEnvironment(new MockEnvironment());
            bridge.postProcessBeanFactory(new DefaultListableBeanFactory());
        }
        assertThat(ProviderAwareChatOptionsFactory.anthropicUsesDefaultSamplingOnly("claude-haiku-4-5"))
                .as("the default version 2023-06-01 keeps the older models' sampling").isFalse();
    }

    /**
     * The post-processor bean methods take nothing: a parameter resolved by type makes Spring create FactoryBeans and
     * what they need while post-processors are registered, and those beans (the chat model on control D) then miss
     * the post-processors.
     */
    @Test
    void thePostProcessorBeanMethodsTakeNothing() {
        assertThat(Arrays.stream(AnthropicChatModelOptionsAutoConfiguration.class.getDeclaredMethods())
                .filter(method -> method.isAnnotationPresent(Bean.class)))
                .isNotEmpty()
                .allMatch(method -> method.getParameterCount() == 0);
        assertThat(Arrays.stream(OllamaChatModelOptionsAutoConfiguration.class.getDeclaredMethods())
                .filter(method -> method.isAnnotationPresent(Bean.class)))
                .isNotEmpty()
                .allMatch(method -> method.getParameterCount() == 0);
    }

    private static ContexaChatModelCopies copies(MockEnvironment environment) {
        return new ContexaChatModelCopies(environment);
    }

    private static AnthropicChatModel model(AnthropicChatOptions options) {
        return AnthropicChatModel.builder().anthropicApi(AnthropicApi.builder().apiKey("test").build())
                .defaultOptions(options).build();
    }
}
