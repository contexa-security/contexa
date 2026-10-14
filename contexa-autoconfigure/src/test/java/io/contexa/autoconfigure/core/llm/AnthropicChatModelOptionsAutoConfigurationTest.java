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
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.anthropic.api.AnthropicCacheOptions;
import org.springframework.ai.anthropic.api.AnthropicCacheStrategy;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.env.MockEnvironment;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Claude Haiku 5.5: the Anthropic chat model's defaults are made fit for the Claude model it runs. Spring AI sets a
 * default temperature of 0.8, which the newest Claude models refuse with a 400 error; and Anthropic caches only the
 * prompt a request marks, so the system prompt is marked unless a cache strategy is configured.
 */
class AnthropicChatModelOptionsAutoConfigurationTest {

    @Test
    void aClaudeModelThatTakesOnlyTheDefaultSamplingLosesTheSpringAiTemperatureAndCachesItsSystemPrompt() {
        AnthropicChatModel model = model(AnthropicChatOptions.builder().model("claude-haiku-5-5").temperature(0.8d)
                .topK(5).maxTokens(500).build());

        processor(new MockEnvironment()).postProcessAfterInitialization(model, "anthropicChatModel");

        AnthropicChatOptions defaults = (AnthropicChatOptions) model.getDefaultOptions();
        assertThat(defaults.getTemperature()).isNull();
        assertThat(defaults.getTopK()).isNull();
        assertThat(defaults.getMaxTokens()).isEqualTo(500);
        assertThat(defaults.getCacheOptions().getStrategy()).isEqualTo(AnthropicCacheStrategy.SYSTEM_ONLY);
    }

    /**
     * A chat model bean created before the post-processors (Spring: "not eligible for getting processed by all
     * BeanPostProcessors", as on control D) is adjusted once every singleton exists.
     */
    @Test
    void aModelCreatedBeforeThePostProcessorsIsAdjustedOnceEverySingletonExists() {
        AnthropicChatModel model = model(AnthropicChatOptions.builder().model("claude-haiku-5-5").temperature(0.8d)
                .maxTokens(500).build());
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton("anthropicChatModel", model);
        AnthropicChatModelPostProcessor processor = processor(new MockEnvironment());

        processor.setBeanFactory(beanFactory);
        processor.afterSingletonsInstantiated();

        AnthropicChatOptions defaults = (AnthropicChatOptions) model.getDefaultOptions();
        assertThat(defaults.getTemperature()).isNull();
        assertThat(defaults.getCacheOptions().getStrategy()).isEqualTo(AnthropicCacheStrategy.SYSTEM_ONLY);
    }

    @Test
    void anOlderClaudeModelKeepsItsSamplingAndAConfiguredCacheStrategyIsKept() {
        AnthropicChatModel model = model(AnthropicChatOptions.builder().model("claude-haiku-4-5").temperature(0.8d)
                .cacheOptions(AnthropicCacheOptions.builder().strategy(AnthropicCacheStrategy.TOOLS_ONLY).build())
                .build());

        processor(new MockEnvironment()).postProcessAfterInitialization(model, "anthropicChatModel");

        AnthropicChatOptions defaults = (AnthropicChatOptions) model.getDefaultOptions();
        assertThat(defaults.getTemperature()).isEqualTo(0.8d);
        assertThat(defaults.getCacheOptions().getStrategy()).isEqualTo(AnthropicCacheStrategy.TOOLS_ONLY);
    }

    @Test
    void theSystemPromptCacheCanBeTurnedOff() {
        AnthropicChatModel model = model(AnthropicChatOptions.builder().model("claude-haiku-5-5").build());

        processor(new MockEnvironment()
                .withProperty("contexa.llm.model-capabilities.anthropic.system-prompt-cache", "false"))
                .postProcessAfterInitialization(model, "anthropicChatModel");

        assertThat(((AnthropicChatOptions) model.getDefaultOptions()).getCacheOptions().getStrategy())
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

    private static AnthropicChatModelPostProcessor processor(MockEnvironment environment) {
        AnthropicChatModelPostProcessor processor = AnthropicChatModelOptionsAutoConfiguration.anthropicChatModelPostProcessor();
        processor.setEnvironment(environment);
        return processor;
    }

    private static AnthropicChatModel model(AnthropicChatOptions options) {
        return AnthropicChatModel.builder().anthropicApi(AnthropicApi.builder().apiKey("test").build())
                .defaultOptions(options).build();
    }
}
