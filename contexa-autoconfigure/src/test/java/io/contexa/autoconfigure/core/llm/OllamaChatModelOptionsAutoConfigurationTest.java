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
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/** The Ollama disable-thinking patterns of the application configuration reach the core without OpenAI. */
class OllamaChatModelOptionsAutoConfigurationTest {

    @Test
    void theConfiguredDisableThinkingPatternsReachTheOptionsFactory() {
        OllamaChatModelOptionsAutoConfiguration.CapabilitiesBridge bridge =
                OllamaChatModelOptionsAutoConfiguration.ollamaModelCapabilitiesEnvironmentBridge();
        bridge.setEnvironment(new MockEnvironment()
                .withProperty(OllamaChatModelOptionsAutoConfiguration.DISABLE_THINKING_PATTERNS,
                        "contexa-thinking-test-model"));
        bridge.postProcessBeanFactory(new DefaultListableBeanFactory());

        Boolean disabled = ReflectionTestUtils.invokeMethod(ProviderAwareChatOptionsFactory.class,
                "shouldDisableOllamaThinking", ExecutionContext.from(new Prompt("p")), "contexa-thinking-test-model");

        assertThat(disabled).isTrue();
    }
}
