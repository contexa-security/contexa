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

import io.contexa.contexacore.config.TieredLLMProperties;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;

@Slf4j
public final class ProviderAwareChatOptionsFactory {

    private static final String OPENAI_CHAT_OPTIONS_CLASS = "org.springframework.ai.openai.OpenAiChatOptions";
    private static final String OPENAI_MAX_COMPLETION_TOKEN_PATTERNS_PROPERTY =
            "contexa.llm.model-capabilities.openai.max-completion-token-patterns";
    private static final String OPENAI_MAX_COMPLETION_TOKEN_PATTERNS_ENV =
            "CONTEXA_LLM_MODEL_CAPABILITIES_OPENAI_MAX_COMPLETION_TOKEN_PATTERNS";
    private static final String OPENAI_DEFAULT_SAMPLING_ONLY_PATTERNS_PROPERTY =
            "contexa.llm.model-capabilities.openai.default-sampling-only-patterns";
    private static final String OPENAI_DEFAULT_SAMPLING_ONLY_PATTERNS_ENV =
            "CONTEXA_LLM_MODEL_CAPABILITIES_OPENAI_DEFAULT_SAMPLING_ONLY_PATTERNS";
    private static final String OLLAMA_DISABLE_THINKING_PATTERNS_PROPERTY =
            "contexa.llm.model-capabilities.ollama.disable-thinking-patterns";
    private static final String OLLAMA_DISABLE_THINKING_PATTERNS_ENV =
            "CONTEXA_LLM_MODEL_CAPABILITIES_OLLAMA_DISABLE_THINKING_PATTERNS";
    private static final AtomicReference<String> CONFIGURED_OPENAI_MODEL = new AtomicReference<>();
    private static final AtomicReference<String> CONFIGURED_OPENAI_MAX_COMPLETION_TOKEN_PATTERNS = new AtomicReference<>();
    private static final AtomicReference<String> CONFIGURED_OPENAI_DEFAULT_SAMPLING_ONLY_PATTERNS = new AtomicReference<>();
    private static final AtomicReference<String> CONFIGURED_OLLAMA_DISABLE_THINKING_PATTERNS = new AtomicReference<>();

    private ProviderAwareChatOptionsFactory() {
    }

    public static void configureModelCapabilities(
            String openAiModel,
            String openAiMaxCompletionTokenPatterns,
            String openAiDefaultSamplingOnlyPatterns,
            String ollamaDisableThinkingPatterns) {
        setIfText(CONFIGURED_OPENAI_MODEL, openAiModel);
        setIfText(CONFIGURED_OPENAI_MAX_COMPLETION_TOKEN_PATTERNS, openAiMaxCompletionTokenPatterns);
        setIfText(CONFIGURED_OPENAI_DEFAULT_SAMPLING_ONLY_PATTERNS, openAiDefaultSamplingOnlyPatterns);
        setIfText(CONFIGURED_OLLAMA_DISABLE_THINKING_PATTERNS, ollamaDisableThinkingPatterns);
    }

    public static ChatOptions normalizeExplicitOptions(ChatOptions options, ExecutionContext context, ChatModel selectedModel) {
        if (options == null) {
            return null;
        }
        String modelName = resolveModelName(context, selectedModel, options);
        boolean isOpenAi = isOpenAiOptions(options);
        boolean requiresMaxCompletion = requiresMaxCompletionTokens(modelName);
        boolean usesDefaultSamplingOnly = usesDefaultSamplingOnly(modelName);

        if (!isOpenAi && isOpenAiModel(selectedModel, context) && requiresMaxCompletion) {
            try {
                Class<?> openAiOptionsClass = loadOpenAiOptionsClass();
                Object builder = openAiOptionsClass.getMethod("builder").invoke(null);
                if (modelName != null && !modelName.isBlank()) {
                    invokeBuilder(builder, "model", String.class, modelName);
                }
                if (!usesDefaultSamplingOnly && options.getTemperature() != null) {
                    invokeBuilder(builder, "temperature", Double.class, options.getTemperature());
                }
                if (!usesDefaultSamplingOnly && options.getTopP() != null) {
                    invokeBuilder(builder, "topP", Double.class, options.getTopP());
                }
                if (options.getMaxTokens() != null) {
                    invokeBuilder(builder, "maxTokens", Integer.class, options.getMaxTokens());
                }
                options = (ChatOptions) invokeNoArg(builder, "build");
                isOpenAi = true;
            } catch (Exception ignored) {
            }
        }

        if (!isOpenAi || !requiresMaxCompletion) {
            return options;
        }

        Object copy = copyOpenAiOptions(options);
        if (usesDefaultSamplingOnly) {
            try {
                invokeSetter(copy, "setTemperature", Double.class, null);
            } catch (Exception ignored) {
            }
            try {
                invokeSetter(copy, "setTopP", Double.class, null);
            } catch (Exception ignored) {
            }
        }

        Integer maxTokens = readInteger(options, "getMaxTokens");
        Integer maxCompletionTokens = readInteger(options, "getMaxCompletionTokens");
        if (maxTokens != null && maxCompletionTokens == null) {
            try {
                invokeSetter(copy, "setMaxCompletionTokens", Integer.class, maxTokens);
                invokeSetter(copy, "setMaxTokens", Integer.class, null);
            } catch (Exception ignored) {
            }
        }
        applyOpenAiRuntimeOptions(copy, context);
        return (ChatOptions) copy;
    }

    public static ChatOptions normalizeModelDefaultOptions(ChatOptions options) {
        if (!isOpenAiOptions(options)) {
            return options;
        }
        String modelName = firstNonBlank(
                readString(options, "getModel"),
                configuredOpenAiModel());
        boolean requiresMaxCompletion = requiresMaxCompletionTokens(modelName);
        boolean usesDefaultSamplingOnly = usesDefaultSamplingOnly(modelName);
        if (!requiresMaxCompletion && !usesDefaultSamplingOnly) {
            return options;
        }
        Object copy = copyOpenAiOptions(options);
        if (modelName != null && !modelName.isBlank()) {
            try {
                invokeSetter(copy, "setModel", String.class, modelName);
            } catch (Exception ignored) {
            }
        }
        if (usesDefaultSamplingOnly) {
            try {
                invokeSetter(copy, "setTemperature", Double.class, null);
            } catch (Exception ignored) {
            }
            try {
                invokeSetter(copy, "setTopP", Double.class, null);
            } catch (Exception ignored) {
            }
        }
        if (requiresMaxCompletion) {
            Integer maxTokens = readInteger(options, "getMaxTokens");
            Integer maxCompletionTokens = readInteger(options, "getMaxCompletionTokens");
            if (maxTokens != null && maxCompletionTokens == null) {
                try {
                    invokeSetter(copy, "setMaxCompletionTokens", Integer.class, maxTokens);
                } catch (Exception ignored) {
                }
            }
            try {
                invokeSetter(copy, "setMaxTokens", Integer.class, null);
            } catch (Exception ignored) {
            }
        }
        return (ChatOptions) copy;
    }

    public static void normalizeModelDefaultOptionsInPlace(ChatModel selectedModel) {
        if (selectedModel == null) {
            return;
        }
        ChatOptions options = mutableDefaultOptions(selectedModel);
        if (!isOpenAiOptions(options)) {
            return;
        }
        String modelName = firstNonBlank(
                readString(options, "getModel"),
                configuredOpenAiModel());
        boolean requiresMaxCompletion = requiresMaxCompletionTokens(modelName);
        boolean usesDefaultSamplingOnly = usesDefaultSamplingOnly(modelName);
        if (!requiresMaxCompletion && !usesDefaultSamplingOnly) {
            return;
        }
        if (modelName != null && !modelName.isBlank()) {
            try {
                invokeSetter(options, "setModel", String.class, modelName);
            } catch (Exception ignored) {
            }
        }
        if (usesDefaultSamplingOnly) {
            try {
                invokeSetter(options, "setTemperature", Double.class, null);
            } catch (Exception ignored) {
            }
            try {
                invokeSetter(options, "setTopP", Double.class, null);
            } catch (Exception ignored) {
            }
        }
        if (requiresMaxCompletion) {
            Integer maxTokens = readInteger(options, "getMaxTokens");
            Integer maxCompletionTokens = readInteger(options, "getMaxCompletionTokens");
            if (maxTokens != null && maxCompletionTokens == null) {
                try {
                    invokeSetter(options, "setMaxCompletionTokens", Integer.class, maxTokens);
                } catch (Exception ignored) {
                }
            }
            try {
                invokeSetter(options, "setMaxTokens", Integer.class, null);
            } catch (Exception ignored) {
            }
        }
    }

    private static ChatOptions mutableDefaultOptions(ChatModel selectedModel) {
        if (selectedModel == null) {
            return null;
        }
        Field defaultOptionsField = findField(selectedModel.getClass(), "defaultOptions");
        if (defaultOptionsField != null) {
            try {
                defaultOptionsField.setAccessible(true);
                Object value = defaultOptionsField.get(selectedModel);
                if (value instanceof ChatOptions chatOptions) {
                    return chatOptions;
                }
            } catch (ReflectiveOperationException | RuntimeException ignored) {
            }
        }
        return selectedModel.getDefaultOptions();
    }

    public static Prompt normalizePromptOptions(Prompt prompt, ExecutionContext context, ChatModel selectedModel) {
        if (prompt == null || prompt.getOptions() == null) {
            return prompt;
        }
        ChatOptions normalizedOptions = normalizeExplicitOptions(prompt.getOptions(), context, selectedModel);
        if (normalizedOptions == prompt.getOptions()) {
            return prompt;
        }
        return new Prompt(prompt.getInstructions(), normalizedOptions);
    }

    public static ChatOptions buildRuntimeOptions(ExecutionContext context, ChatModel selectedModel) {
        return buildRuntimeOptions(context, selectedModel, null);
    }

    public static ChatOptions buildRuntimeOptions(ExecutionContext context, ChatModel selectedModel, TieredLLMProperties tieredLLMProperties) {
        if (context == null) {
            return ChatOptions.builder().build();
        }
        String modelName = resolveModelName(context, selectedModel, null);
        if (isOpenAiModel(selectedModel, context) && requiresMaxCompletionTokens(modelName)) {
            return buildOpenAiCompletionTokenOptions(context, selectedModel, modelName);
        }
        if (isOllamaModel(selectedModel, context)) {
            return buildOllamaOptions(context, selectedModel, tieredLLMProperties);
        }
        return buildGenericChatOptions(context);
    }

    public static boolean requiresProviderSpecificOptions(ExecutionContext context, ChatModel selectedModel) {
        String modelName = resolveModelName(context, selectedModel, null);
        if (isOpenAiModel(selectedModel, context) && requiresMaxCompletionTokens(modelName)) {
            return true;
        }
        return isOllamaModel(selectedModel, context);
    }

    static boolean requiresMaxCompletionTokens(String modelName) {
        return matchesConfiguredModelPattern(
                modelName,
                OPENAI_MAX_COMPLETION_TOKEN_PATTERNS_PROPERTY,
                OPENAI_MAX_COMPLETION_TOKEN_PATTERNS_ENV);
    }

    static boolean usesDefaultSamplingOnly(String modelName) {
        return matchesConfiguredModelPattern(
                modelName,
                OPENAI_DEFAULT_SAMPLING_ONLY_PATTERNS_PROPERTY,
                OPENAI_DEFAULT_SAMPLING_ONLY_PATTERNS_ENV);
    }

    private static ChatOptions buildGenericChatOptions(ExecutionContext context) {
        ChatOptions.Builder optionsBuilder = ChatOptions.builder();
        if (context.getPreferredModel() != null && !context.getPreferredModel().isBlank()) {
            optionsBuilder.model(context.getPreferredModel());
        }
        if (context.getTemperature() != null) {
            optionsBuilder.temperature(context.getTemperature());
        }
        if (context.getTopP() != null) {
            optionsBuilder.topP(context.getTopP());
        }
        if (context.getMaxTokens() != null) {
            optionsBuilder.maxTokens(context.getMaxTokens());
        }
        return optionsBuilder.build();
    }

    private static ChatOptions buildOpenAiCompletionTokenOptions(
            ExecutionContext context,
            ChatModel selectedModel,
            String modelName) {
        Object builder = openAiBuilderFromDefaultOptions(selectedModel);
        if (modelName != null && !modelName.isBlank()) {
            invokeBuilder(builder, "model", String.class, modelName);
        }
        boolean usesDefaultSamplingOnly = usesDefaultSamplingOnly(modelName);
        if (usesDefaultSamplingOnly) {
            invokeBuilder(builder, "temperature", Double.class, null);
            invokeBuilder(builder, "topP", Double.class, null);
        }
        if (!usesDefaultSamplingOnly && context.getTemperature() != null) {
            invokeBuilder(builder, "temperature", Double.class, context.getTemperature());
        }
        if (!usesDefaultSamplingOnly && context.getTopP() != null) {
            invokeBuilder(builder, "topP", Double.class, context.getTopP());
        }
        if (context.getMaxTokens() != null) {
            invokeBuilder(builder, "maxCompletionTokens", Integer.class, context.getMaxTokens());
            invokeBuilder(builder, "maxTokens", Integer.class, null);
        } else {
            Integer defaultMaxTokens = selectedModel != null
                    ? readInteger(selectedModel.getDefaultOptions(), "getMaxTokens")
                    : null;
            Integer defaultMaxCompletionTokens = selectedModel != null
                    ? readInteger(selectedModel.getDefaultOptions(), "getMaxCompletionTokens")
                    : null;
            if (defaultMaxTokens != null && defaultMaxCompletionTokens == null) {
                invokeBuilder(builder, "maxCompletionTokens", Integer.class, defaultMaxTokens);
            }
            invokeBuilder(builder, "maxTokens", Integer.class, null);
        }
        ChatOptions options = (ChatOptions) invokeNoArg(builder, "build");
        applyOpenAiRuntimeOptions(options, context);
        return options;
    }

    private static void applyOpenAiRuntimeOptions(Object options, ExecutionContext context) {
        if (!isOpenAiOptions(options) || context == null) {
            return;
        }
        String reasoningEffort = firstNonBlank(
                metadataText(context, "openAiReasoningEffort"),
                metadataText(context, "runtimeOpenAiReasoningEffort"));
        if (reasoningEffort != null) {
            invokeSetter(options, "setReasoningEffort", String.class, reasoningEffort);
            context.addMetadata("openAiReasoningEffort", reasoningEffort);
        }
        String verbosity = firstNonBlank(
                metadataText(context, "openAiVerbosity"),
                metadataText(context, "runtimeOpenAiVerbosity"));
        if (verbosity != null) {
            invokeSetter(options, "setVerbosity", String.class, verbosity);
            context.addMetadata("openAiVerbosity", verbosity);
        }
    }
    private static Object openAiBuilderFromDefaultOptions(ChatModel selectedModel) {
        ChatOptions defaultOptions = selectedModel != null ? selectedModel.getDefaultOptions() : null;
        if (isOpenAiOptions(defaultOptions)) {
            Class<?> optionsClass = loadOpenAiOptionsClass();
            try {
                Method fromOptions = optionsClass.getMethod("fromOptions", optionsClass);
                Object copied = fromOptions.invoke(null, defaultOptions);
                return optionsClass.getMethod("builder").invoke(null).getClass()
                        .getConstructor(optionsClass)
                        .newInstance(copied);
            } catch (ReflectiveOperationException ignored) {
                Object copy = copyOpenAiOptions(defaultOptions);
                try {
                    return optionsClass.getMethod("builder").invoke(null).getClass()
                            .getConstructor(optionsClass)
                            .newInstance(copy);
                } catch (ReflectiveOperationException nested) {
                    throw new IllegalStateException("OpenAI chat options builder cannot copy default options", nested);
                }
            }
        }
        try {
            return loadOpenAiOptionsClass().getMethod("builder").invoke(null);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("OpenAI chat options builder is unavailable", e);
        }
    }

    private static Object copyOpenAiOptions(Object options) {
        if (options == null) {
            return null;
        }
        try {
            return options.getClass().getMethod("copy").invoke(options);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("OpenAI chat options cannot be copied", e);
        }
    }

    private static boolean isOpenAiModel(ChatModel selectedModel, ExecutionContext context) {
        if (selectedModel != null && selectedModel.getClass().getName().toLowerCase(Locale.ROOT).contains(".openai.")) {
            return true;
        }
        Object provider = context != null ? context.getMetadata().get("selectedModelProvider") : null;
        if (provider != null && String.valueOf(provider).trim().equalsIgnoreCase("openai")) {
            return true;
        }
        return "openai".equalsIgnoreCase(configuredChatProvider());
    }

    private static boolean isOpenAiOptions(Object options) {
        return options != null && options.getClass().getName().equals(OPENAI_CHAT_OPTIONS_CLASS);
    }

    private static String resolveModelName(ExecutionContext context, ChatModel selectedModel, ChatOptions explicitOptions) {
        String explicitRequest = null;
        String selectedModelHint = null;
        ChatOptions defaultOptions = selectedModel != null ? selectedModel.getDefaultOptions() : null;
        if (context != null) {
            explicitRequest = firstNonBlank(
                    context.getPreferredModel(),
                    metadataText(context, "preferredModel"),
                    metadataText(context, "requestedModelId"));
            selectedModelHint = firstNonBlank(
                    metadataText(context, "runtimeModelId"),
                    metadataText(context, "selectedModelId"),
                    metadataText(context, "providerResponseModel"));
        }
        if (isOpenAiModel(selectedModel, context) || isOpenAiOptions(explicitOptions) || isOpenAiOptions(defaultOptions)) {
            return firstNonBlank(
                    readString(explicitOptions, "getModel"),
                    readString(defaultOptions, "getModel"),
                    configuredOpenAiModel(),
                    explicitRequest,
                    selectedModelHint);
        }
        return firstNonBlank(
                explicitRequest,
                readString(explicitOptions, "getModel"),
                readString(defaultOptions, "getModel"),
                configuredOpenAiModel(),
                selectedModelHint);
    }

    private static String configuredOpenAiModel() {
        return firstNonBlank(
                System.getProperty("spring.ai.openai.chat.options.model"),
                System.getenv("SPRING_AI_OPENAI_CHAT_OPTIONS_MODEL"),
                CONFIGURED_OPENAI_MODEL.get());
    }

    private static String configuredChatProvider() {
        return firstNonBlank(
                System.getProperty("contexa.llm.selection.chat.priority"),
                System.getenv("CONTEXA_LLM_SELECTION_CHAT_PRIORITY"));
    }

    private static boolean matchesConfiguredModelPattern(String modelName, String propertyName, String envName) {
        if (modelName == null || modelName.isBlank()) {
            return false;
        }
        String configuredPatterns = firstNonBlank(
                System.getProperty(propertyName),
                System.getenv(envName),
                configuredPatternOverride(propertyName));
        if (configuredPatterns == null || configuredPatterns.isBlank()) {
            return false;
        }
        String resolvedModelName = modelName.trim();
        for (String rawPattern : configuredPatterns.split("[,;\\r\\n]+")) {
            String pattern = rawPattern.trim();
            if (pattern.isEmpty()) {
                continue;
            }
            try {
                if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(resolvedModelName).matches()) {
                    return true;
                }
            } catch (PatternSyntaxException ex) {
                log.error("Ignoring invalid LLM model capability pattern '{}' from {}", pattern, propertyName);
            }
        }
        return false;
    }

    private static String configuredPatternOverride(String propertyName) {
        return switch (propertyName) {
            case OPENAI_MAX_COMPLETION_TOKEN_PATTERNS_PROPERTY -> CONFIGURED_OPENAI_MAX_COMPLETION_TOKEN_PATTERNS.get();
            case OPENAI_DEFAULT_SAMPLING_ONLY_PATTERNS_PROPERTY -> CONFIGURED_OPENAI_DEFAULT_SAMPLING_ONLY_PATTERNS.get();
            case OLLAMA_DISABLE_THINKING_PATTERNS_PROPERTY -> CONFIGURED_OLLAMA_DISABLE_THINKING_PATTERNS.get();
            default -> null;
        };
    }

    private static void setIfText(AtomicReference<String> target, String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        target.set(value.trim());
    }

    private static String metadataText(ExecutionContext context, String key) {
        Object value = context.getMetadata().get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private static Class<?> loadOpenAiOptionsClass() {
        try {
            return Class.forName(OPENAI_CHAT_OPTIONS_CLASS);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("OpenAI chat options are not on the runtime classpath", e);
        }
    }

    private static Object invokeNoArg(Object target, String methodName) {
        try {
            return target.getClass().getMethod(methodName).invoke(target);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot invoke " + methodName + " on " + target.getClass().getName(), e);
        }
    }

    private static void invokeBuilder(Object builder, String methodName, Class<?> parameterType, Object value) {
        try {
            builder.getClass().getMethod(methodName, parameterType).invoke(builder, value);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot set OpenAI option " + methodName, e);
        }
    }

    private static void invokeSetter(Object target, String methodName, Class<?> parameterType, Object value) {
        try {
            target.getClass().getMethod(methodName, parameterType).invoke(target, value);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot set OpenAI option " + methodName, e);
        }
    }

    private static Integer readInteger(Object target, String methodName) {
        Object value = invokeGetter(target, methodName);
        return value instanceof Integer integer ? integer : null;
    }

    private static String readString(Object target, String methodName) {
        Object value = invokeGetter(target, methodName);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    private static Object invokeGetter(Object target, String methodName) {
        if (target == null) {
            return null;
        }
        try {
            return target.getClass().getMethod(methodName).invoke(target);
        } catch (ReflectiveOperationException ignored) {
            return null;
        }
    }

    private static Field findField(Class<?> type, String name) {
        Class<?> current = type;
        while (current != null && current != Object.class) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ex) {
                current = current.getSuperclass();
            }
        }
        return null;
    }

    private static boolean isOllamaModel(ChatModel selectedModel, ExecutionContext context) {
        if (selectedModel != null && selectedModel.getClass().getName().toLowerCase(Locale.ROOT).contains(".ollama.")) {
            return true;
        }
        Object provider = context != null ? context.getMetadata().get("selectedModelProvider") : null;
        return provider != null && String.valueOf(provider).trim().equalsIgnoreCase("ollama");
    }

    @SuppressWarnings("unchecked")
    private static ChatOptions buildOllamaOptions(ExecutionContext context, ChatModel selectedModel, TieredLLMProperties tieredLLMProperties) {
        try {
            String modelName = determineOllamaModelName(context, selectedModel, tieredLLMProperties);
            ChatOptions defaultOptions = selectedModel.getDefaultOptions();
            Class<?> optionsClass = Class.forName("org.springframework.ai.ollama.api.OllamaChatOptions");
            Object optionsBuilder = optionsClass.getMethod("builder").invoke(null);
            Object options = optionsBuilder.getClass().getMethod("build").invoke(optionsBuilder);

            if (defaultOptions != null && optionsClass.isInstance(defaultOptions)) {
                options = optionsClass.getMethod("fromOptions", optionsClass).invoke(null, defaultOptions);
            }

            if (modelName != null && !modelName.isBlank()) {
                optionsClass.getMethod("setModel", String.class).invoke(options, modelName);
            }
            if (context.getTemperature() != null) {
                optionsClass.getMethod("setTemperature", Double.class).invoke(options, context.getTemperature());
            }
            if (context.getTopP() != null) {
                optionsClass.getMethod("setTopP", Double.class).invoke(options, context.getTopP());
            }
            if (context.getSeed() != null) {
                optionsClass.getMethod("setSeed", Integer.class).invoke(options, context.getSeed());
            }
            if (context.getMaxTokens() != null) {
                optionsClass.getMethod("setNumPredict", Integer.class).invoke(options, context.getMaxTokens());
            }
            if (shouldDisableOllamaThinking(context, modelName)) {
                Class<?> thinkOptionClass = Class.forName("org.springframework.ai.ollama.api.ThinkOption$ThinkBoolean");
                Object disabledEnum = Enum.valueOf((Class<Enum>) thinkOptionClass, "DISABLED");
                Class<?> thinkOptionInterface = Class.forName("org.springframework.ai.ollama.api.ThinkOption");
                optionsClass.getMethod("setThinkOption", thinkOptionInterface).invoke(options, disabledEnum);
            }

            return (ChatOptions) options;
        } catch (Exception e) {
            log.error("Failed to build Ollama options via reflection", e);
            return selectedModel.getDefaultOptions();
        }
    }

    private static String determineOllamaModelName(ExecutionContext context, ChatModel selectedModel, TieredLLMProperties tieredLLMProperties) {
        String selectedModelId = resolveSelectedModelId(context);
        if (selectedModelId != null) {
            return selectedModelId;
        }

        if (context.getPreferredModel() != null && !context.getPreferredModel().isEmpty()) {
            return context.getPreferredModel();
        }

        if (context.getAnalysisLevel() != null) {
            int tier = context.getAnalysisLevel().getDefaultTier();
            return tieredLLMProperties != null ? tieredLLMProperties.getModelNameForTier(tier) : "qwen2.5:7b";
        }

        if (context.getTier() != null) {
            return resolveConfiguredModelNameForTier(context.getTier(), tieredLLMProperties);
        }

        if (context.getSecurityTaskType() != null) {
            int tier = context.getSecurityTaskType().getDefaultTier();
            return tieredLLMProperties != null ? tieredLLMProperties.getModelNameForTier(tier) : "qwen2.5:7b";
        }

        String defaultModel = resolveConfiguredModelNameForTier(1, tieredLLMProperties);
        log.error("Model selection unavailable, using default model: {}", defaultModel);
        return defaultModel;
    }

    public static String resolveSelectedModelId(ExecutionContext context) {
        if (context == null || context.getMetadata() == null) {
            return null;
        }
        for (String key : List.of("selectedModelId", "runtimeModelId", "requestedModelId")) {
            Object value = context.getMetadata().get(key);
            if (value != null) {
                String text = String.valueOf(value).trim();
                if (!text.isEmpty()) {
                    return text;
                }
            }
        }
        return null;
    }

    private static String resolveConfiguredModelNameForTier(Integer tier, TieredLLMProperties tieredLLMProperties) {
        if (tieredLLMProperties == null) {
            return "qwen2.5:7b";
        }
        if (tier == null || tier <= 1) {
            return tieredLLMProperties.getModelNameForTier(1);
        }
        return tieredLLMProperties.getModelNameForTier(Math.min(tier, 2));
    }

    private static boolean shouldDisableOllamaThinking(ExecutionContext context, String modelName) {
        if (context == null) {
            return false;
        }
        Object metadataValue = context.getMetadata() != null ? context.getMetadata().get("disableOllamaThinking") : null;
        if (metadataValue instanceof Boolean bool) {
            return bool;
        }
        if (metadataValue instanceof String text) {
            return Boolean.parseBoolean(text);
        }
        if (modelName == null) {
            return false;
        }
        return matchesConfiguredModelPattern(
                modelName,
                OLLAMA_DISABLE_THINKING_PATTERNS_PROPERTY,
                OLLAMA_DISABLE_THINKING_PATTERNS_ENV);
    }
}
