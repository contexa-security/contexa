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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import io.contexa.contexacore.std.llm.client.vertexai.VertexLikeChatModel;
import io.contexa.contexacore.std.llm.model.ChatModelVariants;
import org.slf4j.LoggerFactory;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.anthropic.api.AnthropicCacheOptions;
import org.springframework.ai.anthropic.api.AnthropicCacheStrategy;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.ai.ollama.api.ThinkOption;
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
    private static final String OLLAMA_DISABLE_THINKING_PATTERNS_PROPERTY =
            "contexa.llm.model-capabilities.ollama.disable-thinking-patterns";

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

    /**
     * R-9: the default options of a chat model Contexa did not make (the application's, as the application has it) are
     * the application's: Contexa sets nothing in them, though its own calls on the model would leave them out.
     */
    @Test
    @DisplayName("Contexa가 만들지 않은 채팅 모델의 실제 기본 옵션은 제자리에서 바뀌지 않는다")
    void anApplicationsModelKeepsItsActualOpenAiDefaultOptions() {
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

            assertThat(chatModel.actualDefaultOptions.getTemperature()).isEqualTo(0.7d);
            assertThat(chatModel.actualDefaultOptions.getTopP()).isEqualTo(0.9d);
            assertThat(chatModel.actualDefaultOptions.getMaxTokens()).isEqualTo(256);
            assertThat(chatModel.actualDefaultOptions.getMaxCompletionTokens()).isNull();
        } finally {
            clearOpenAiCapabilities();
        }
    }

    /**
     * The defaults of a chat model Contexa made for its own calls are set in place, where Spring AI reads them: a request
     * cannot take a default out, so a reasoning model's sampling and max_tokens leave the defaults themselves.
     */
    @Test
    @DisplayName("Contexa가 만든 채팅 모델 인스턴스의 실제 기본 옵션은 제자리에서 그 모델이 받는 값으로 맞춘다")
    void contexasOwnModelHasItsActualOpenAiDefaultOptionsSetInPlace() {
        configureOpenAiCapabilities(CAPABILITY_MODEL);
        try {
            CopyingOpenAiDefaultOptionsChatModel chatModel = ContexaChatModelInstances.add(
                    new CopyingOpenAiDefaultOptionsChatModel(OpenAiChatOptions.builder()
                            .model(CAPABILITY_MODEL)
                            .maxTokens(256)
                            .temperature(0.7d)
                            .topP(0.9d)
                            .build()));

            ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(chatModel);

            assertThat(chatModel.actualDefaultOptions.getTemperature()).isNull();
            assertThat(chatModel.actualDefaultOptions.getTopP()).isNull();
            assertThat(chatModel.actualDefaultOptions.getMaxTokens()).isNull();
            assertThat(chatModel.actualDefaultOptions.getMaxCompletionTokens()).isEqualTo(256);
        } finally {
            clearOpenAiCapabilities();
        }
    }

    /**
     * The first Contexa call on an application's model whose defaults hold what Contexa leaves out of its own instances'
     * defaults is reported once, with the fields, and the defaults stay; a model with none of them is not reported.
     */
    @Test
    @DisplayName("앱 채팅 모델의 기본 옵션에 Contexa가 뺄 값이 있으면 한 번만 error 로그로 알리고 옵션은 그대로 둔다")
    void anApplicationsDefaultsContexaWouldLeaveOutAreReportedOnce() {
        Logger logger = (Logger) LoggerFactory.getLogger(ProviderAwareChatOptionsFactory.class);
        ListAppender<ILoggingEvent> logged = new ListAppender<>();
        logged.start();
        logger.addAppender(logged);
        try {
            AnthropicChatModel refusing = anthropicModel("claude-haiku-5-5");
            AnthropicChatModel older = anthropicModel("claude-haiku-4-5");

            ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(refusing);
            ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(refusing);
            ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(older);

            List<String> errors = logged.list.stream().filter(event -> event.getLevel() == Level.ERROR)
                    .map(ILoggingEvent::getFormattedMessage).toList();
            assertThat(errors).hasSize(1);
            assertThat(errors.get(0)).contains(AnthropicChatModel.class.getName()).contains("claude-haiku-5-5")
                    .contains("[temperature, top_k]");
            assertThat(((AnthropicChatOptions) refusing.getDefaultOptions()).getTemperature()).isEqualTo(0.8d);
        } finally {
            logger.detachAppender(logged);
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
     * D-7 (QF-51): the Claude models that refuse any sampling value but the default are the Claude API's list (thinking
     * and migration documentation, read 2026-10-30): Opus 4.7 and later, Sonnet 5 and 5.5, Haiku 5.5, Fable and Mythos.
     */
    @Test
    void theClaudeModelsThatTakeOnlyTheDefaultSamplingAreTheClaudeApisList() {
        for (String model : List.of("claude-opus-4-7", "claude-opus-4-8", "claude-opus-5", "claude-opus-5-5",
                "claude-sonnet-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5", "claude-fable-5-1",
                "claude-mythos-5", "claude-mythos-5-1", "claude-mythos-preview")) {
            assertThat(ProviderAwareChatOptionsFactory.anthropicUsesDefaultSamplingOnly(model)).as(model).isTrue();
        }
        for (String model : List.of("claude-opus-4-6", "claude-sonnet-4-6", "claude-opus-4-5", "claude-haiku-4-5",
                "claude-sonnet-4-5-20250929")) {
            assertThat(ProviderAwareChatOptionsFactory.anthropicUsesDefaultSamplingOnly(model)).as(model).isFalse();
        }
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
     * R-9: the application's Claude model keeps Spring AI's default temperature (0.8), which Claude Haiku 5.5 refuses:
     * the application set it, and Contexa sets nothing in a model it did not make.
     */
    @Test
    @DisplayName("앱의 Claude 모델은 그 모델이 거절하는 기본 샘플링도 앱이 준 그대로 둔다")
    void anApplicationsClaudeModelKeepsItsDefaultSampling() {
        AnthropicChatModel newer = anthropicModel("claude-haiku-5-5");

        ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(newer);

        AnthropicChatOptions newerDefaults = (AnthropicChatOptions) newer.getDefaultOptions();
        assertThat(newerDefaults.getTemperature()).isEqualTo(0.8d);
        assertThat(newerDefaults.getTopK()).isEqualTo(5);
        assertThat(newerDefaults.getMaxTokens()).isEqualTo(500);
    }

    /**
     * Contexa's own instance of a Claude model loses the sampling the model refuses (Spring AI's 0.8 included) from its
     * defaults before a call, and an older Claude model keeps it; the application's model it was made from keeps its own.
     */
    @Test
    @DisplayName("Contexa 인스턴스의 Claude 모델만 그 모델이 거절하는 기본 샘플링을 호출 전에 뺀다")
    void contexasClaudeInstanceLosesTheRefusedDefaultSamplingBeforeACall() {
        AnthropicChatModel application = anthropicModel("claude-haiku-5-5");
        ChatModel newer = ChatModelVariants.copyOf(application).orElseThrow();
        ChatModel older = ChatModelVariants.copyOf(anthropicModel("claude-haiku-4-5")).orElseThrow();

        ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(newer);
        ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(older);

        AnthropicChatOptions newerDefaults = (AnthropicChatOptions) newer.getDefaultOptions();
        assertThat(newerDefaults.getTemperature()).isNull();
        assertThat(newerDefaults.getTopK()).isNull();
        assertThat(newerDefaults.getMaxTokens()).isEqualTo(500);
        assertThat(((AnthropicChatOptions) older.getDefaultOptions()).getTemperature()).isEqualTo(0.8d);
        assertThat(((AnthropicChatOptions) application.getDefaultOptions()).getTemperature()).isEqualTo(0.8d);
        assertThat(((AnthropicChatOptions) application.getDefaultOptions()).getTopK()).isEqualTo(5);
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

    @Test
    void buildRuntimeOptionsShouldTurnOffTheThinkingOfAnOllamaModelNamedByTheConfiguredPattern() {
        ExecutionContext context = ollamaContext("qwen3:8b");
        System.setProperty(OLLAMA_DISABLE_THINKING_PATTERNS_PROPERTY, "qwen3.*");
        try {
            ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(context, ollamaModel("qwen3:8b"));

            // Spring AI's ThinkBoolean is a record with static ENABLED/DISABLED, not an enum: it used to throw
            // "ThinkBoolean is not an enum class" and the call lost every runtime option.
            assertThat(options).isInstanceOf(OllamaChatOptions.class);
            OllamaChatOptions ollamaOptions = (OllamaChatOptions) options;
            assertThat(ollamaOptions.getThinkOption()).isEqualTo(ThinkOption.ThinkBoolean.DISABLED);
            assertThat(ollamaOptions.getModel()).isEqualTo("qwen3:8b");
            assertThat(ollamaOptions.getNumPredict()).isEqualTo(2048);
            assertThat(ollamaOptions.getTemperature()).isEqualTo(0.0d);
        } finally {
            System.clearProperty(OLLAMA_DISABLE_THINKING_PATTERNS_PROPERTY);
        }
    }

    @Test
    void buildRuntimeOptionsShouldTurnOffTheThinkingOfAnOllamaModelWhenTheCallAsksFor() {
        ExecutionContext context = ollamaContext("qwen3:8b");
        context.addMetadata("disableOllamaThinking", true);

        ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(context, ollamaModel("qwen3:8b"));

        assertThat(options).isInstanceOf(OllamaChatOptions.class);
        assertThat(((OllamaChatOptions) options).getThinkOption()).isEqualTo(ThinkOption.ThinkBoolean.DISABLED);
    }

    @Test
    void buildRuntimeOptionsShouldLeaveTheThinkingOfAnOllamaModelAloneWhenNoPatternNamesIt() {
        ExecutionContext context = ollamaContext("llama3.1:8b");
        System.setProperty(OLLAMA_DISABLE_THINKING_PATTERNS_PROPERTY, "qwen3.*");
        try {
            ChatOptions options = ProviderAwareChatOptionsFactory.buildRuntimeOptions(context, ollamaModel("llama3.1:8b"));

            assertThat(options).isInstanceOf(OllamaChatOptions.class);
            OllamaChatOptions ollamaOptions = (OllamaChatOptions) options;
            assertThat(ollamaOptions.getThinkOption()).isNull();
            assertThat(ollamaOptions.getModel()).isEqualTo("llama3.1:8b");
            assertThat(ollamaOptions.getNumPredict()).isEqualTo(2048);
        } finally {
            System.clearProperty(OLLAMA_DISABLE_THINKING_PATTERNS_PROPERTY);
        }
    }

    /**
     * K13: every call asks for the same context, 16,384 tokens by default, so one model runner serves them all (Ollama
     * reloads the model for another length); a short prompt fits it.
     */
    @Test
    void anOllamaCallAsksForTheConfiguredContextWhenItsPromptFits() {
        ExecutionContext context = ollamaContext("qwen3:8b");

        OllamaChatOptions options = (OllamaChatOptions) ProviderAwareChatOptionsFactory.buildRuntimeOptions(context,
                ollamaModel("qwen3:8b"));

        assertThat(options.getNumCtx()).isEqualTo(16_384);
        assertThat(context.getMetadata().get(ExecutionContext.PROVIDER_CONTEXT_LENGTH)).isEqualTo(16_384);
        assertThat(context.getMetadata().get(ExecutionContext.ESTIMATED_PROMPT_TOKENS)).isEqualTo(5);
    }

    /**
     * K13: a decision prompt of about 6,800 tokens with a 4,096-token answer limit was cut to the server's 4,096 tokens;
     * it fits the default context, and a longer one gets the context doubled until it fits.
     */
    @Test
    void anOllamaCallAsksForAContextItsPromptAndAnswerFitIn() {
        ExecutionContext decision = ollamaContext("qwen3:8b", "x".repeat(27_000));
        decision.setMaxTokens(4_096);
        ExecutionContext longer = ollamaContext("qwen3:8b", "x".repeat(45_000));
        longer.setMaxTokens(4_096);

        OllamaChatOptions fits = (OllamaChatOptions) ProviderAwareChatOptionsFactory.buildRuntimeOptions(decision,
                ollamaModel("qwen3:8b"));
        OllamaChatOptions doubled = (OllamaChatOptions) ProviderAwareChatOptionsFactory.buildRuntimeOptions(longer,
                ollamaModel("qwen3:8b"));

        // 27,000 bytes are estimated at 9,000 tokens; with 4,096 for the answer and 256 for the template, 13,352
        assertThat(decision.getMetadata().get(ExecutionContext.ESTIMATED_PROMPT_TOKENS)).isEqualTo(9_000);
        assertThat(fits.getNumCtx()).isEqualTo(16_384);
        assertThat(fits.getNumPredict()).isEqualTo(4_096);
        // 45,000 bytes: 15,000 + 4,096 + 256 = 19,352
        assertThat(doubled.getNumCtx()).isEqualTo(32_768);
    }

    /** K13: the configured context replaces the default one. */
    @Test
    void anOllamaCallAsksForTheContextTheConfigurationNames() {
        ProviderAwareChatOptionsFactory.configureOllamaContextLength(8_192);
        try {
            OllamaChatOptions options = (OllamaChatOptions) ProviderAwareChatOptionsFactory.buildRuntimeOptions(
                    ollamaContext("qwen3:8b"), ollamaModel("qwen3:8b"));

            assertThat(options.getNumCtx()).isEqualTo(8_192);
        } finally {
            ProviderAwareChatOptionsFactory.configureOllamaContextLength(null);
        }
    }

    /** K13: a Korean syllable takes three bytes and about one token, so the estimate stays above the true count. */
    @Test
    void theEstimateCountsAKoreanSyllableAsAToken() {
        assertThat(ProviderAwareChatOptionsFactory.estimatedPromptTokens(new Prompt("가".repeat(300)))).isEqualTo(300);
        assertThat(ProviderAwareChatOptionsFactory.estimatedPromptTokens(null)).isZero();
    }

    /** K13: an operator's num_ctx is where the call starts; it grows from there when the prompt needs more. */
    @Test
    void anOllamaCallStartsFromTheConfiguredContext() {
        ChatModel model = new StubChatModel(OllamaChatOptions.builder().model("qwen3:8b").numCtx(8_192).build());

        OllamaChatOptions small = (OllamaChatOptions) ProviderAwareChatOptionsFactory.buildRuntimeOptions(
                ollamaContext("qwen3:8b"), model);
        ExecutionContext large = ollamaContext("qwen3:8b", "x".repeat(30_000));
        large.setMaxTokens(4_096);
        OllamaChatOptions grown = (OllamaChatOptions) ProviderAwareChatOptionsFactory.buildRuntimeOptions(large, model);

        assertThat(small.getNumCtx()).isEqualTo(8_192);
        assertThat(grown.getNumCtx()).isEqualTo(16_384);
    }

    /** K13: the context stops at the configured largest one; the prompt that does not fit it is logged as cut. */
    @Test
    void anOllamaCallStopsAtTheLargestConfiguredContext() {
        ProviderAwareChatOptionsFactory.configureOllamaContextLength(4_096);
        ProviderAwareChatOptionsFactory.configureOllamaMaxContextLength(8_192);
        try {
            ExecutionContext context = ollamaContext("qwen3:8b", "x".repeat(60_000));

            OllamaChatOptions options = (OllamaChatOptions) ProviderAwareChatOptionsFactory.buildRuntimeOptions(context,
                    ollamaModel("qwen3:8b"));

            assertThat(options.getNumCtx()).isEqualTo(8_192);
        } finally {
            ProviderAwareChatOptionsFactory.configureOllamaMaxContextLength(null);
            ProviderAwareChatOptionsFactory.configureOllamaContextLength(null);
        }
    }

    /** K13: a server that read its whole context as input cut the prompt; the call says so. */
    @Test
    void aModelServerThatReadItsWholeContextCutThePrompt() {
        ExecutionContext cut = ollamaContext("qwen3:8b");
        cut.addMetadata(ExecutionContext.PROVIDER_CONTEXT_LENGTH, 4_096);
        ExecutionContext whole = ollamaContext("qwen3:8b");
        whole.addMetadata(ExecutionContext.PROVIDER_CONTEXT_LENGTH, 16_384);
        ExecutionContext unknown = ollamaContext("qwen3:8b");

        UnifiedLLMOrchestrator.recordProviderTruncation(cut, 4_096);
        UnifiedLLMOrchestrator.recordProviderTruncation(whole, 6_805);
        UnifiedLLMOrchestrator.recordProviderTruncation(unknown, 6_805);

        assertThat(cut.getMetadata().get(ExecutionContext.PROMPT_TRUNCATED_BY_PROVIDER)).isEqualTo(true);
        assertThat(whole.getMetadata()).doesNotContainKey(ExecutionContext.PROMPT_TRUNCATED_BY_PROVIDER);
        assertThat(unknown.getMetadata()).doesNotContainKey(ExecutionContext.PROMPT_TRUNCATED_BY_PROVIDER);
    }

    private static ExecutionContext ollamaContext(String model) {
        return ollamaContext(model, "security prompt");
    }

    private static ExecutionContext ollamaContext(String model, String promptText) {
        ExecutionContext context = ExecutionContext.from(new Prompt(promptText));
        context.setMaxTokens(2048);
        context.setTemperature(0.0d);
        context.setPreferredModel(model);
        context.addMetadata("selectedModelProvider", "ollama");
        return context;
    }

    private static ChatModel ollamaModel(String model) {
        return new StubChatModel(OllamaChatOptions.builder().model(model).build());
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
