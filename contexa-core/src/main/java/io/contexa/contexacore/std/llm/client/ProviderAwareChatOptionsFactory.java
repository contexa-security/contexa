package io.contexa.contexacore.std.llm.client;

import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;

import java.lang.reflect.Method;
import java.util.Locale;

public final class ProviderAwareChatOptionsFactory {

    private static final String OPENAI_CHAT_OPTIONS_CLASS = "org.springframework.ai.openai.OpenAiChatOptions";

    private ProviderAwareChatOptionsFactory() {
    }

    public static ChatOptions normalizeExplicitOptions(ChatOptions options, ExecutionContext context, ChatModel selectedModel) {
        if (options == null) {
            return null;
        }
        String modelName = resolveModelName(context, selectedModel, options);
        if (!isOpenAiOptions(options) || !requiresMaxCompletionTokens(modelName)) {
            return options;
        }
        Integer maxTokens = readInteger(options, "getMaxTokens");
        Integer maxCompletionTokens = readInteger(options, "getMaxCompletionTokens");
        if (maxTokens == null || maxCompletionTokens != null) {
            return options;
        }
        Object copy = copyOpenAiOptions(options);
        invokeSetter(copy, "setMaxCompletionTokens", Integer.class, maxTokens);
        invokeSetter(copy, "setMaxTokens", Integer.class, null);
        return (ChatOptions) copy;
    }

    public static ChatOptions buildRuntimeOptions(ExecutionContext context, ChatModel selectedModel) {
        if (context == null) {
            return ChatOptions.builder().build();
        }
        String modelName = resolveModelName(context, selectedModel, null);
        if (isOpenAiModel(selectedModel, context) && requiresMaxCompletionTokens(modelName)) {
            return buildOpenAiCompletionTokenOptions(context, selectedModel, modelName);
        }
        return buildGenericChatOptions(context);
    }

    public static boolean requiresProviderSpecificOptions(ExecutionContext context, ChatModel selectedModel) {
        String modelName = resolveModelName(context, selectedModel, null);
        return isOpenAiModel(selectedModel, context) && requiresMaxCompletionTokens(modelName);
    }

    static boolean requiresMaxCompletionTokens(String modelName) {
        if (modelName == null || modelName.isBlank()) {
            return false;
        }
        String normalized = modelName.trim().toLowerCase(Locale.ROOT);
        return normalized.startsWith("gpt-5")
                || normalized.startsWith("o1")
                || normalized.startsWith("o3")
                || normalized.startsWith("o4");
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
        if (context.getTemperature() != null) {
            invokeBuilder(builder, "temperature", Double.class, context.getTemperature());
        }
        if (context.getTopP() != null) {
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
        return (ChatOptions) invokeNoArg(builder, "build");
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
        return provider != null && String.valueOf(provider).trim().equalsIgnoreCase("openai");
    }

    private static boolean isOpenAiOptions(Object options) {
        return options != null && options.getClass().getName().equals(OPENAI_CHAT_OPTIONS_CLASS);
    }

    private static String resolveModelName(ExecutionContext context, ChatModel selectedModel, ChatOptions explicitOptions) {
        if (context != null) {
            String preferred = firstNonBlank(
                    context.getPreferredModel(),
                    metadataText(context, "runtimeModelId"),
                    metadataText(context, "requestedModelId"),
                    metadataText(context, "selectedModelId"),
                    metadataText(context, "providerResponseModel"));
            if (preferred != null) {
                return preferred;
            }
        }
        String explicitModel = readString(explicitOptions, "getModel");
        if (explicitModel != null) {
            return explicitModel;
        }
        ChatOptions defaultOptions = selectedModel != null ? selectedModel.getDefaultOptions() : null;
        return readString(defaultOptions, "getModel");
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
}
