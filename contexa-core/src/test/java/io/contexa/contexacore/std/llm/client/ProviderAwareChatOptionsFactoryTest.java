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

    private static final String CAPABILITY_MODEL = "capability-test-model";
    private static final String LEGACY_MODEL = "legacy-chat-model";
    private static final String MAX_COMPLETION_PATTERNS_PROPERTY =
            "contexa.llm.model-capabilities.openai.max-completion-token-patterns";
    private static final String DEFAULT_SAMPLING_PATTERNS_PROPERTY =
            "contexa.llm.model-capabilities.openai.default-sampling-only-patterns";

    @Test
    void buildRuntimeOptionsShouldUseConfiguredOpenAiCapabilities() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(96);
        context.setTemperature(0.0d);
        context.setTopP(0.5d);
        context.addMetadata("selectedModelProvider", "openai");
        configureOpenAiCapabilities(CAPABILITY_MODEL);

        ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(
                context,
                new StubChatModel(OpenAiChatOptions.builder()
                        .model(CAPABILITY_MODEL)
                        .temperature(0.7d)
                        .topP(0.9d)
                        .build()));

        assertThat(options).isInstanceOf(OpenAiChatOptions.class);
        OpenAiChatOptions openAiOptions = (OpenAiChatOptions) options;
        assertThat(openAiOptions.getModel()).isEqualTo(CAPABILITY_MODEL);
        assertThat(openAiOptions.getMaxTokens()).isNull();
        assertThat(openAiOptions.getMaxCompletionTokens()).isEqualTo(96);
        assertThat(openAiOptions.getTemperature()).isNull();
        assertThat(openAiOptions.getTopP()).isNull();
        clearOpenAiCapabilities();
    }

    @Test
    void buildRuntimeOptionsShouldApplyRuntimeOpenAiReasoningAndVerbosity() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(96);
        context.addMetadata("selectedModelProvider", "openai");
        context.addMetadata("openAiReasoningEffort", "minimal");
        context.addMetadata("openAiVerbosity", "low");
        configureOpenAiCapabilities(CAPABILITY_MODEL);

        ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(
                context,
                new StubChatModel(OpenAiChatOptions.builder()
                        .model(CAPABILITY_MODEL)
                        .temperature(0.7d)
                        .topP(0.9d)
                        .build()));

        assertThat(options).isInstanceOf(OpenAiChatOptions.class);
        OpenAiChatOptions openAiOptions = (OpenAiChatOptions) options;
        assertThat(openAiOptions.getReasoningEffort()).isEqualTo("minimal");
        assertThat(openAiOptions.getVerbosity()).isEqualTo("low");
        assertThat(openAiOptions.getMaxTokens()).isNull();
        assertThat(openAiOptions.getMaxCompletionTokens()).isEqualTo(96);
        clearOpenAiCapabilities();
    }
    @Test
    void normalizeExplicitOptionsShouldApplyConfiguredOpenAiCapabilities() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        ChatOptions explicitOptions = OpenAiChatOptions.builder()
                .model(CAPABILITY_MODEL)
                .maxTokens(128)
                .temperature(0.7d)
                .topP(0.9d)
                .build();

        ChatOptions normalized = ProviderAwareChatOptionsFactory.normalizeExplicitOptions(
                explicitOptions,
                context,
                new StubChatModel(explicitOptions));

        assertThat(normalized).isInstanceOf(OpenAiChatOptions.class);
        OpenAiChatOptions openAiOptions = (OpenAiChatOptions) normalized;
        assertThat(openAiOptions.getMaxTokens()).isNull();
        assertThat(openAiOptions.getMaxCompletionTokens()).isEqualTo(128);
        assertThat(openAiOptions.getTemperature()).isNull();
        assertThat(openAiOptions.getTopP()).isNull();
        clearOpenAiCapabilities();
    }

    @Test
    void normalizeExplicitOptionsShouldKeepLegacyOpenAiMaxTokens() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        ChatOptions explicitOptions = OpenAiChatOptions.builder()
                .model(LEGACY_MODEL)
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
        clearOpenAiCapabilities();
    }

    @Test
    void normalizeExplicitOptionsShouldUseConfiguredOpenAiModelWhenOptionModelIsMissing() {
        String previous = System.getProperty("spring.ai.openai.chat.options.model");
        System.setProperty("spring.ai.openai.chat.options.model", CAPABILITY_MODEL);
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
            context.addMetadata("selectedModelProvider", "openai");
            ChatOptions explicitOptions = ChatOptions.builder()
                    .temperature(0.7d)
                    .topP(0.9d)
                    .maxTokens(128)
                    .build();

            ChatOptions normalized = ProviderAwareChatOptionsFactory.normalizeExplicitOptions(
                    explicitOptions,
                    context,
                    new StubChatModel(OpenAiChatOptions.builder().build()));

            assertThat(normalized).isInstanceOf(OpenAiChatOptions.class);
            OpenAiChatOptions openAiOptions = (OpenAiChatOptions) normalized;
            assertThat(openAiOptions.getMaxTokens()).isNull();
            assertThat(openAiOptions.getMaxCompletionTokens()).isEqualTo(128);
            assertThat(openAiOptions.getTemperature()).isNull();
            assertThat(openAiOptions.getTopP()).isNull();
        } finally {
            clearOpenAiCapabilities();
            if (previous == null) {
                System.clearProperty("spring.ai.openai.chat.options.model");
            } else {
                System.setProperty("spring.ai.openai.chat.options.model", previous);
            }
        }
    }

    @Test
    void normalizeExplicitOptionsShouldPreferConfiguredOpenAiModelOverLogicalContextModel() {
        String previous = System.getProperty("spring.ai.openai.chat.options.model");
        System.setProperty("spring.ai.openai.chat.options.model", CAPABILITY_MODEL);
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
            context.setPreferredModel("logical-tier-model");
            context.addMetadata("runtimeModelId", "logical-runtime-id");
            context.addMetadata("selectedModelProvider", "openai");
            ChatOptions explicitOptions = ChatOptions.builder()
                    .temperature(0.7d)
                    .topP(0.9d)
                    .maxTokens(128)
                    .build();

            ChatOptions normalized = ProviderAwareChatOptionsFactory.normalizeExplicitOptions(
                    explicitOptions,
                    context,
                    new StubChatModel(OpenAiChatOptions.builder().build()));

            assertThat(normalized).isInstanceOf(OpenAiChatOptions.class);
            OpenAiChatOptions openAiOptions = (OpenAiChatOptions) normalized;
            assertThat(openAiOptions.getModel()).isEqualTo(CAPABILITY_MODEL);
            assertThat(openAiOptions.getMaxTokens()).isNull();
            assertThat(openAiOptions.getMaxCompletionTokens()).isEqualTo(128);
            assertThat(openAiOptions.getTemperature()).isNull();
            assertThat(openAiOptions.getTopP()).isNull();
        } finally {
            clearOpenAiCapabilities();
            if (previous == null) {
                System.clearProperty("spring.ai.openai.chat.options.model");
            } else {
                System.setProperty("spring.ai.openai.chat.options.model", previous);
            }
        }
    }

    @Test
    void normalizeExplicitOptionsShouldUseConfiguredProviderWhenModelClassIsWrapped() {
        String previousModel = System.getProperty("spring.ai.openai.chat.options.model");
        String previousProvider = System.getProperty("contexa.llm.selection.chat.priority");
        System.setProperty("spring.ai.openai.chat.options.model", CAPABILITY_MODEL);
        System.setProperty("contexa.llm.selection.chat.priority", "openai");
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
            ChatOptions explicitOptions = ChatOptions.builder()
                    .temperature(0.7d)
                    .topP(0.9d)
                    .maxTokens(128)
                    .build();

            ChatOptions normalized = ProviderAwareChatOptionsFactory.normalizeExplicitOptions(
                    explicitOptions,
                    context,
                    new StubChatModel(ChatOptions.builder().build()));

            assertThat(normalized).isInstanceOf(OpenAiChatOptions.class);
            OpenAiChatOptions openAiOptions = (OpenAiChatOptions) normalized;
            assertThat(openAiOptions.getModel()).isEqualTo(CAPABILITY_MODEL);
            assertThat(openAiOptions.getMaxTokens()).isNull();
            assertThat(openAiOptions.getMaxCompletionTokens()).isEqualTo(128);
            assertThat(openAiOptions.getTemperature()).isNull();
            assertThat(openAiOptions.getTopP()).isNull();
        } finally {
            clearOpenAiCapabilities();
            if (previousModel == null) {
                System.clearProperty("spring.ai.openai.chat.options.model");
            } else {
                System.setProperty("spring.ai.openai.chat.options.model", previousModel);
            }
            if (previousProvider == null) {
                System.clearProperty("contexa.llm.selection.chat.priority");
            } else {
                System.setProperty("contexa.llm.selection.chat.priority", previousProvider);
            }
        }
    }

    @Test
    void buildRuntimeOptionsShouldConvertDefaultOpenAiMaxTokensWhenCapabilityRequiresIt() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.addMetadata("selectedModelProvider", "openai");
        configureOpenAiCapabilities(CAPABILITY_MODEL);

        ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(
                context,
                new StubChatModel(OpenAiChatOptions.builder()
                        .model(CAPABILITY_MODEL)
                        .maxTokens(256)
                        .temperature(0.7d)
                        .topP(0.9d)
                        .build()));

        assertThat(options).isInstanceOf(OpenAiChatOptions.class);
        OpenAiChatOptions openAiOptions = (OpenAiChatOptions) options;
        assertThat(openAiOptions.getMaxTokens()).isNull();
        assertThat(openAiOptions.getMaxCompletionTokens()).isEqualTo(256);
        assertThat(openAiOptions.getTemperature()).isNull();
        assertThat(openAiOptions.getTopP()).isNull();
        clearOpenAiCapabilities();
    }

    @Test
    void normalizeModelDefaultOptionsInPlaceShouldMutateActualOpenAiDefaultOptions() {
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            CopyingOpenAiDefaultOptionsChatModel chatModel = new CopyingOpenAiDefaultOptionsChatModel(
                    OpenAiChatOptions.builder()
                            .model(CAPABILITY_MODEL)
                            .maxTokens(256)
                            .temperature(0.7d)
                            .topP(0.9d)
                            .build());

            ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(chatModel);

            assertThat(chatModel.actualDefaultOptions.getTemperature()).isNull();
            assertThat(chatModel.actualDefaultOptions.getTopP()).isNull();
            assertThat(chatModel.actualDefaultOptions.getMaxTokens()).isNull();
            assertThat(chatModel.actualDefaultOptions.getMaxCompletionTokens()).isEqualTo(256);
        } finally {
            clearOpenAiCapabilities();
        }
    }

    private static void configureOpenAiCapabilities(String modelName) {
        String escaped = "\\Q" + modelName + "\\E";
        System.setProperty(MAX_COMPLETION_PATTERNS_PROPERTY, escaped);
        System.setProperty(DEFAULT_SAMPLING_PATTERNS_PROPERTY, escaped);
    }

    private static void clearOpenAiCapabilities() {
        System.clearProperty(MAX_COMPLETION_PATTERNS_PROPERTY);
        System.clearProperty(DEFAULT_SAMPLING_PATTERNS_PROPERTY);
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

    private static final class CopyingOpenAiDefaultOptionsChatModel implements ChatModel {

        private final OpenAiChatOptions defaultOptions;
        private final OpenAiChatOptions actualDefaultOptions;

        private CopyingOpenAiDefaultOptionsChatModel(OpenAiChatOptions defaultOptions) {
            this.defaultOptions = defaultOptions;
            this.actualDefaultOptions = defaultOptions;
        }

        @Override
        public ChatResponse call(Prompt prompt) {
            throw new UnsupportedOperationException("not used");
        }

        @Override
        public ChatOptions getDefaultOptions() {
            return defaultOptions.copy();
        }
    }
}
