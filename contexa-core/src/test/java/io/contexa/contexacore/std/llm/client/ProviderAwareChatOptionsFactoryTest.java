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

import java.util.List;
import org.junit.jupiter.api.Test;
import io.contexa.contexacore.std.llm.client.vertexai.VertexLikeChatModel;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.anthropic.api.AnthropicCacheOptions;
import org.springframework.ai.anthropic.api.AnthropicCacheStrategy;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.ResponseFormat;

import static org.assertj.core.api.Assertions.assertThat;

class ProviderAwareChatOptionsFactoryTest {

    private static final String CAPABILITY_MODEL = "capability-test-model";
    private static final String LEGACY_MODEL = "legacy-chat-model";
    private static final String OUTPUT_SCHEMA = "{\"type\":\"object\",\"additionalProperties\":false,"
            + "\"required\":[\"action\"],\"properties\":{\"action\":{\"type\":\"string\"}}}";
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

    /** W3-8: the prompt cache key of the request goes to OpenAI with the other runtime options. */
    @Test
    void buildRuntimeOptionsShouldSendThePromptCacheKey() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(96);
        context.addMetadata("selectedModelProvider", "openai");
        context.addMetadata("promptCacheKey", "contexa-0123456789abcdef");
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(
                    context,
                    new StubChatModel(OpenAiChatOptions.builder().model(CAPABILITY_MODEL).build()));

            assertThat(options).isInstanceOf(OpenAiChatOptions.class);
            assertThat(((OpenAiChatOptions) options).getPromptCacheKey()).isEqualTo("contexa-0123456789abcdef");
            assertThat(context.getMetadata()).containsEntry("promptCacheKeyApplied", true);
        } finally {
            clearOpenAiCapabilities();
        }
    }

    /**
     * W3-8: an OpenAI model outside the completion token rule gets the prompt cache key too, and nothing else of the
     * reasoning model options (an older model refuses a reasoning effort).
     */
    @Test
    void anOpenAiModelOutsideTheCompletionTokenRuleGetsOnlyThePromptCacheKey() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(96);
        context.setTemperature(0.2d);
        context.addMetadata("selectedModelProvider", "openai");
        context.addMetadata("openAiReasoningEffort", "minimal");
        context.addMetadata("promptCacheKey", "contexa-0123456789abcdef");
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            StubChatModel model = new StubChatModel(OpenAiChatOptions.builder().model(LEGACY_MODEL).build());

            assertThat(ProviderAwareChatOptionsFactory.requiresProviderSpecificOptions(context, model)).isTrue();
            ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(context, model);

            assertThat(options).isInstanceOf(OpenAiChatOptions.class);
            OpenAiChatOptions openAiOptions = (OpenAiChatOptions) options;
            assertThat(openAiOptions.getPromptCacheKey()).isEqualTo("contexa-0123456789abcdef");
            assertThat(openAiOptions.getModel()).isEqualTo(LEGACY_MODEL);
            assertThat(openAiOptions.getMaxTokens()).isEqualTo(96);
            assertThat(openAiOptions.getMaxCompletionTokens()).isNull();
            assertThat(openAiOptions.getTemperature()).isEqualTo(0.2d);
            assertThat(openAiOptions.getReasoningEffort()).isNull();
            assertThat(context.getMetadata()).containsEntry("promptCacheKeyApplied", true);
        } finally {
            clearOpenAiCapabilities();
        }
    }

    /** W3-8: explicit OpenAI options of an older model get the key on a copy; the caller's options stay as they were. */
    @Test
    void normalizeExplicitOptionsShouldAddThePromptCacheKeyToACopy() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.addMetadata("promptCacheKey", "contexa-0123456789abcdef");
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            OpenAiChatOptions explicitOptions = OpenAiChatOptions.builder().model(LEGACY_MODEL).maxTokens(128).build();

            ChatOptions normalized = ProviderAwareChatOptionsFactory.normalizeExplicitOptions(
                    explicitOptions, context, new StubChatModel(explicitOptions));

            assertThat(normalized).isInstanceOf(OpenAiChatOptions.class).isNotSameAs(explicitOptions);
            assertThat(((OpenAiChatOptions) normalized).getPromptCacheKey()).isEqualTo("contexa-0123456789abcdef");
            assertThat(((OpenAiChatOptions) normalized).getMaxTokens()).isEqualTo(128);
            assertThat(explicitOptions.getPromptCacheKey()).isNull();
        } finally {
            clearOpenAiCapabilities();
        }
    }

    /** W3-8: without a prompt cache key an older OpenAI model keeps the generic options, as before. */
    @Test
    void withoutAPromptCacheKeyAnOlderOpenAiModelKeepsTheGenericOptions() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(96);
        context.addMetadata("selectedModelProvider", "openai");
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            StubChatModel model = new StubChatModel(OpenAiChatOptions.builder().model(LEGACY_MODEL).build());

            assertThat(ProviderAwareChatOptionsFactory.requiresProviderSpecificOptions(context, model)).isFalse();
            assertThat(ProviderAwareChatOptionsFactory.buildRuntimeOptions(context, model))
                    .isNotInstanceOf(OpenAiChatOptions.class);
            assertThat(context.getMetadata()).doesNotContainKey("promptCacheKeyApplied");
        } finally {
            clearOpenAiCapabilities();
        }
    }

    /** W4-2: a reasoning model gets the output schema as a strict JSON schema response format. */
    @Test
    void buildRuntimeOptionsShouldEnforceTheOutputSchema() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(96);
        context.addMetadata("selectedModelProvider", "openai");
        context.addMetadata(ExecutionContext.OUTPUT_SCHEMA, OUTPUT_SCHEMA);
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(
                    context,
                    new StubChatModel(OpenAiChatOptions.builder().model(CAPABILITY_MODEL).build()));

            assertThat(options).isInstanceOf(OpenAiChatOptions.class);
            ResponseFormat format = ((OpenAiChatOptions) options).getResponseFormat();
            assertThat(format).isNotNull();
            assertThat(format.getType()).isEqualTo(ResponseFormat.Type.JSON_SCHEMA);
            assertThat(format.getJsonSchema().getStrict()).isTrue();
            assertThat(format.getJsonSchema().getSchema()).containsEntry("additionalProperties", false);
            assertThat(((OpenAiChatOptions) options).getMaxCompletionTokens()).isEqualTo(96);
            assertThat(context.getMetadata()).containsEntry(ExecutionContext.OUTPUT_SCHEMA_APPLIED, true);
        } finally {
            clearOpenAiCapabilities();
        }
    }

    /** W4-2: an OpenAI model outside the completion token rule takes the provider options to carry the schema. */
    @Test
    void anOpenAiModelOutsideTheCompletionTokenRuleGetsTheOutputSchema() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(96);
        context.addMetadata("selectedModelProvider", "openai");
        context.addMetadata(ExecutionContext.OUTPUT_SCHEMA, OUTPUT_SCHEMA);
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            StubChatModel model = new StubChatModel(OpenAiChatOptions.builder().model(LEGACY_MODEL).build());

            assertThat(ProviderAwareChatOptionsFactory.requiresProviderSpecificOptions(context, model)).isTrue();
            ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(context, model);

            assertThat(options).isInstanceOf(OpenAiChatOptions.class);
            assertThat(((OpenAiChatOptions) options).getResponseFormat().getType())
                    .isEqualTo(ResponseFormat.Type.JSON_SCHEMA);
            assertThat(((OpenAiChatOptions) options).getMaxTokens()).isEqualTo(96);
            assertThat(context.getMetadata()).containsEntry(ExecutionContext.OUTPUT_SCHEMA_APPLIED, true);
        } finally {
            clearOpenAiCapabilities();
        }
    }

    /** W4-2: explicit options get the schema on a copy; the caller's options stay as they were. */
    @Test
    void normalizeExplicitOptionsShouldPutTheOutputSchemaOnACopy() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.addMetadata(ExecutionContext.OUTPUT_SCHEMA, OUTPUT_SCHEMA);
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            OpenAiChatOptions explicitOptions = OpenAiChatOptions.builder().model(LEGACY_MODEL).maxTokens(128).build();

            ChatOptions normalized = ProviderAwareChatOptionsFactory.normalizeExplicitOptions(
                    explicitOptions, context, new StubChatModel(explicitOptions));

            assertThat(normalized).isInstanceOf(OpenAiChatOptions.class).isNotSameAs(explicitOptions);
            assertThat(((OpenAiChatOptions) normalized).getResponseFormat().getType())
                    .isEqualTo(ResponseFormat.Type.JSON_SCHEMA);
            assertThat(((OpenAiChatOptions) normalized).getMaxTokens()).isEqualTo(128);
            assertThat(explicitOptions.getResponseFormat()).isNull();
        } finally {
            clearOpenAiCapabilities();
        }
    }

    /** W4-2: options that cannot carry a schema get none and the context does not claim it went out. */
    @Test
    void optionsWithoutStructuredOutputGetNoSchema() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(96);
        context.addMetadata(ExecutionContext.OUTPUT_SCHEMA, OUTPUT_SCHEMA);

        ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(
                context, new StubChatModel(ChatOptions.builder().model("plain-model").build()));

        assertThat(options).isNotInstanceOf(OpenAiChatOptions.class);
        assertThat(context.getMetadata()).doesNotContainKey(ExecutionContext.OUTPUT_SCHEMA_APPLIED);
    }

    /**
     * Claude Haiku 5.5: an Anthropic model keeps its own option type, so the prompt cache its defaults configure goes
     * out (Spring AI turns generic options into new Anthropic options whose cache is off, and those override the
     * defaults); the model's defaults stay as they are.
     */
    @Test
    void anAnthropicModelKeepsItsOptionTypeAndItsPromptCache() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(2048);
        AnthropicChatOptions defaults = AnthropicChatOptions.builder().model("claude-haiku-5-5").maxTokens(500)
                .cacheOptions(AnthropicCacheOptions.builder().strategy(AnthropicCacheStrategy.SYSTEM_ONLY).build())
                .build();

        ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(context, new StubChatModel(defaults));

        assertThat(options).isInstanceOf(AnthropicChatOptions.class);
        AnthropicChatOptions anthropic = (AnthropicChatOptions) options;
        assertThat(anthropic.getModel()).isEqualTo("claude-haiku-5-5");
        assertThat(anthropic.getMaxTokens()).isEqualTo(2048);
        assertThat(anthropic.getCacheOptions().getStrategy()).isEqualTo(AnthropicCacheStrategy.SYSTEM_ONLY);
        assertThat(defaults.getMaxTokens()).as("the model's defaults stay as they are").isEqualTo(500);
    }

    /**
     * Claude Haiku 5.5 refuses any sampling value but the default (a 400 error), so it gets no temperature or top-p;
     * Claude Haiku 4.5 still takes them.
     */
    @Test
    void anAnthropicModelThatTakesOnlyTheDefaultSamplingGetsNoSamplingValues() {
        assertThat(ProviderAwareChatOptionsFactory.anthropicUsesDefaultSamplingOnly("claude-haiku-5-5")).isTrue();
        assertThat(ProviderAwareChatOptionsFactory.anthropicUsesDefaultSamplingOnly("claude-opus-4-7")).isTrue();
        assertThat(ProviderAwareChatOptionsFactory.anthropicUsesDefaultSamplingOnly("claude-haiku-4-5")).isFalse();

        ChatOptions newer = anthropicOptionsWithSampling("claude-haiku-5-5");
        assertThat(newer.getTemperature()).isNull();
        assertThat(newer.getTopP()).isNull();
        ChatOptions older = anthropicOptionsWithSampling("claude-haiku-4-5");
        assertThat(older.getTemperature()).isEqualTo(0.2d);
        assertThat(older.getTopP()).isEqualTo(0.5d);
    }

    /**
     * A model of another provider (here one whose package names Vertex AI) is never given OpenAI options because the
     * configured chat priority names OpenAI.
     */
    @Test
    void anotherProvidersModelGetsNoOpenAiOptionsWhenThePriorityNamesOpenAi() {
        String previous = System.getProperty("contexa.llm.selection.chat.priority");
        System.setProperty("contexa.llm.selection.chat.priority", "openai");
        try {
            ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
            context.setMaxTokens(64);
            context.addMetadata("promptCacheKey", "contexa-0123456789abcdef0123456789abcdef");

            ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(context,
                    new VertexLikeChatModel());

            assertThat(options).isNotInstanceOf(OpenAiChatOptions.class);
            assertThat(options.getMaxTokens()).isEqualTo(64);
        }
        finally {
            if (previous == null) {
                System.clearProperty("contexa.llm.selection.chat.priority");
            }
            else {
                System.setProperty("contexa.llm.selection.chat.priority", previous);
            }
        }
    }

    /**
     * A Claude model whose bean was created before the post-processors still has Spring AI's default temperature (0.8),
     * which Claude Haiku 5.5 refuses; its defaults lose the refused sampling in place before a call, and an older
     * Claude model keeps them.
     */
    @Test
    void aClaudeModelsRefusedDefaultSamplingIsTakenOutInPlaceBeforeACall() {
        AnthropicChatModel newer = anthropicModel("claude-haiku-5-5");
        AnthropicChatModel older = anthropicModel("claude-haiku-4-5");

        ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(newer);
        ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(older);

        AnthropicChatOptions newerDefaults = (AnthropicChatOptions) newer.getDefaultOptions();
        assertThat(newerDefaults.getTemperature()).isNull();
        assertThat(newerDefaults.getTopK()).isNull();
        assertThat(newerDefaults.getMaxTokens()).isEqualTo(500);
        assertThat(((AnthropicChatOptions) older.getDefaultOptions()).getTemperature()).isEqualTo(0.8d);
    }

    /**
     * W4-2: Anthropic refuses an output schema with a keyword its structured outputs do not support (HTTP 400 "property
     * 'maxItems' is not supported", checked on the API); an Anthropic request carries the schema without them, and
     * keeps the keywords it supports (a minimum of 0 or 1 items, patterns, enumerations).
     */
    @Test
    void anAnthropicRequestCarriesTheOutputSchemaWithoutTheKeywordsAnthropicRefuses() {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(2048);
        context.addMetadata(ExecutionContext.OUTPUT_SCHEMA, "{\"type\":\"object\",\"additionalProperties\":false,"
                + "\"required\":[\"codes\",\"score\"],\"properties\":{\"codes\":{\"type\":\"array\",\"minItems\":1,"
                + "\"maxItems\":5,\"items\":{\"type\":\"string\",\"pattern\":\"^F[0-9]$\",\"maxLength\":3}},"
                + "\"score\":{\"type\":[\"number\",\"null\"],\"minimum\":0,\"maximum\":1}}}");

        ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(context,
                new StubChatModel(AnthropicChatOptions.builder().model("claude-haiku-5-5").build()));

        String schema = ((AnthropicChatOptions) options).getOutputSchema();
        assertThat(schema).doesNotContain("maxItems").doesNotContain("minimum").doesNotContain("maximum")
                .doesNotContain("maxLength")
                .contains("\"minItems\":1").contains("\"pattern\":\"^F[0-9]$\"").contains("\"additionalProperties\":false");
        assertThat(context.getMetadata()).containsEntry(ExecutionContext.OUTPUT_SCHEMA_APPLIED, true);
    }

    /**
     * W4-6: the determinism settings a provider takes are set and the ones it does not take are recorded on the call
     * (checked on the APIs 2026-10-14: gpt-6-luna takes a seed and not temperature 0; claude-haiku-5-5 takes neither).
     */
    @Test
    void theDeterminismAProviderDoesNotTakeIsRecordedOnTheCall() {
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            ExecutionContext openAi = ExecutionContext.from(new Prompt("security prompt"));
            openAi.setTemperature(0.0d);
            openAi.setSeed(1);
            openAi.addMetadata("selectedModelProvider", "openai");

            ChatOptions openAiOptions = ProviderAwareChatOptionsFactory.buildRuntimeOptions(openAi,
                    new StubChatModel(OpenAiChatOptions.builder().model(CAPABILITY_MODEL).build()));

            assertThat(((OpenAiChatOptions) openAiOptions).getSeed()).isEqualTo(1);
            assertThat(openAiOptions.getTemperature()).isNull();
            assertThat(openAi.getMetadata()).containsEntry(ExecutionContext.DETERMINISM_NOT_APPLIED, List.of("temperature"));
        } finally {
            clearOpenAiCapabilities();
        }
        ExecutionContext anthropic = ExecutionContext.from(new Prompt("security prompt"));
        anthropic.setTemperature(0.0d);
        anthropic.setSeed(1);

        ProviderAwareChatOptionsFactory.buildRuntimeOptions(anthropic,
                new StubChatModel(AnthropicChatOptions.builder().model("claude-haiku-5-5").build()));

        assertThat(anthropic.getMetadata())
                .containsEntry(ExecutionContext.DETERMINISM_NOT_APPLIED, List.of("temperature", "seed"));
    }

    /** W4-6: the reasoning effort the options carry is recorded on the call; a model that takes none records none. */
    @Test
    void theReasoningEffortSentIsRecordedOnTheCall() {
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            ExecutionContext reasoning = ExecutionContext.from(new Prompt("security prompt"));
            reasoning.setMaxTokens(96);
            reasoning.addMetadata("selectedModelProvider", "openai");
            reasoning.addMetadata("openAiReasoningEffort", "low");
            ExecutionContext legacy = ExecutionContext.from(new Prompt("security prompt"));
            legacy.setMaxTokens(96);
            legacy.addMetadata("selectedModelProvider", "openai");
            legacy.addMetadata("openAiReasoningEffort", "low");

            ProviderAwareChatOptionsFactory.buildRuntimeOptions(reasoning,
                    new StubChatModel(OpenAiChatOptions.builder().model(CAPABILITY_MODEL).build()));
            ProviderAwareChatOptionsFactory.buildRuntimeOptions(legacy,
                    new StubChatModel(OpenAiChatOptions.builder().model(LEGACY_MODEL).build()));

            assertThat(reasoning.getMetadata()).containsEntry(ExecutionContext.PROVIDER_REASONING_EFFORT, "low");
            assertThat(legacy.getMetadata()).doesNotContainKey(ExecutionContext.PROVIDER_REASONING_EFFORT);
        } finally {
            clearOpenAiCapabilities();
        }
    }

    private static AnthropicChatModel anthropicModel(String model) {
        return AnthropicChatModel.builder()
                .anthropicApi(AnthropicApi.builder().apiKey("test").build())
                .defaultOptions(AnthropicChatOptions.builder().model(model).temperature(0.8d).topK(5).maxTokens(500)
                        .build())
                .build();
    }

    private static ChatOptions anthropicOptionsWithSampling(String model) {
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.setMaxTokens(2048);
        context.setTemperature(0.2d);
        context.setTopP(0.5d);
        return ProviderAwareChatOptionsFactory.buildRuntimeOptions(context,
                new StubChatModel(AnthropicChatOptions.builder().model(model).build()));
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
