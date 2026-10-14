/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 */
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.core.autonomous.CoreAutonomousEventAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Claude Haiku 5.5: the decision observation records the chat provider Spring AI runs and its model; another provider's
 * model property that is also set (an application that can switch providers) does not make it that provider.
 */
class CoreAutonomousEventModelProviderTest {

    @Test
    void theChatProviderSpringAiRunsIsRecordedWithItsModel() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.ai.model.chat", "anthropic")
                .withProperty("spring.ai.openai.chat.options.model", "gpt-6-luna")
                .withProperty("spring.ai.anthropic.chat.options.model", "claude-haiku-5-5");

        assertThat(provider(environment)).isEqualTo("anthropic");
        assertThat(modelId(environment)).isEqualTo("claude-haiku-5-5");
    }

    @Test
    void withoutAChatProviderTheFirstProviderWithAModelIsRecorded() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.ai.anthropic.chat.options.model", "claude-haiku-5-5");

        assertThat(provider(environment)).isEqualTo("anthropic");
        assertThat(modelId(environment)).isEqualTo("claude-haiku-5-5");
    }

    private static String provider(MockEnvironment environment) {
        return ReflectionTestUtils.invokeMethod(CoreAutonomousEventAutoConfiguration.class, "defaultModelProvider",
                environment);
    }

    private static String modelId(MockEnvironment environment) {
        return ReflectionTestUtils.invokeMethod(CoreAutonomousEventAutoConfiguration.class, "defaultModelId",
                environment);
    }
}
