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

import io.contexa.contexacore.std.llm.client.AnthropicThinkingRules.Settings;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.model.ModelOptionsUtils;

/**
 * The thinking, effort and output limit an Anthropic model call carries for the layer's settings, with what the model
 * takes (the capability table), what Spring AI on the class path can send, and the fields the provider has refused for
 * the model. Spring AI 1.1 merges a request's options over the model's default options and drops a request's null, so
 * a field the model refuses is also taken out of the model's defaults in place, as the default sampling of the newest
 * Claude models already is. Every field left out or changed is recorded on the call.
 */
@Slf4j
final class AnthropicThinkingOptions {

    /** The field groups a provider refusal may name; effort is never sent through Spring AI 1.1. */
    static final String THINKING = "thinking";
    static final String SAMPLING = "sampling";

    /** The call's internal keys: the model the request named and the fields it carried. */
    static final String REQUEST_MODEL = "anthropicRequestModel";
    static final String SENT_FIELDS = "anthropicSentFields";
    /** The field groups the provider refused on this call's first request, left out of its one resend. */
    static final String RESEND_GROUPS = "anthropicResendFieldGroups";

    static final String OFF_NOT_POSSIBLE_ALWAYS_ON = "OFF_NOT_POSSIBLE_ALWAYS_ON";
    static final String OFF_WITH_EFFORT_NOT_ACCEPTED = "OFF_WITH_EFFORT_NOT_ACCEPTED";
    static final String BUDGET_NOT_ACCEPTED_BY_MODEL = "BUDGET_NOT_ACCEPTED_BY_MODEL";
    static final String BUDGET_TOKENS_NOT_VALID = "BUDGET_TOKENS_NOT_VALID";
    static final String ADAPTIVE_NOT_ACCEPTED_BY_MODEL = "ADAPTIVE_NOT_ACCEPTED_BY_MODEL";
    static final String EFFORT_NOT_SUPPORTED = "EFFORT_NOT_SUPPORTED";
    static final String NOT_EXPRESSIBLE_SPRING_AI_1_1 = "NOT_EXPRESSIBLE_SPRING_AI_1_1";
    static final String PROVIDER_REJECTED_RESENT_WITHOUT_THINKING = "PROVIDER_REJECTED_RESENT_WITHOUT_THINKING";
    static final String PROVIDER_REJECTED_RESENT_WITHOUT_SAMPLING = "PROVIDER_REJECTED_RESENT_WITHOUT_SAMPLING";
    static final String PROVIDER_REJECTED_EARLIER_LEFT_OUT = "PROVIDER_REJECTED_EARLIER_LEFT_OUT";

    static final String SOURCE_LAYER_SETTING = "LAYER_SETTING";
    static final String SOURCE_SPRING_AI_DEFAULT_OPTIONS = "SPRING_AI_DEFAULT_OPTIONS";
    static final String SOURCE_MODEL_DEFAULT = "MODEL_DEFAULT";

    private static final String DISABLED = "disabled";
    private static final String ENABLED = "enabled";
    private static final String ADAPTIVE = "adaptive";
    private static final String BETWEEN_TOOLS = "between_tools";
    private static final List<String> SAMPLING_FIELDS = List.of("temperature", "top_p", "top_k");
    private static final List<String> RECORD_KEYS = List.of(
            ExecutionContext.PROVIDER_THINKING_REQUESTED,
            ExecutionContext.PROVIDER_EFFORT_REQUESTED,
            ExecutionContext.PROVIDER_THINKING,
            ExecutionContext.PROVIDER_THINKING_BUDGET_TOKENS,
            ExecutionContext.PROVIDER_THINKING_SOURCE,
            ExecutionContext.PROVIDER_THINKING_ADJUSTMENT,
            ExecutionContext.PROVIDER_REJECTED_FIELDS,
            ExecutionContext.PROVIDER_MAX_TOKENS_SENT,
            REQUEST_MODEL,
            SENT_FIELDS);

    /** The field groups each model refused, for the process's lifetime (model ids in lower case). */
    private static final Map<String, Set<String>> REFUSED = new ConcurrentHashMap<>();
    /** The model and field groups whose refusal was logged. */
    private static final Set<String> LOGGED = ConcurrentHashMap.newKeySet();

    private AnthropicThinkingOptions() {
    }

    /** The thinking a request sends: its type in the Claude API's words and its budget. */
    private record Thinking(String type, Integer budgetTokens) {
    }

    /** A resend in flight: the model, the groups it registered as refused and the defaults it took out in place. */
    record Resend(String model, Set<String> groups, Set<String> registered, Map<String, Object> removedDefaults) {
    }

    /** The layer settings the call carries; the defaults when it carries none. */
    static Settings settingsOf(ExecutionContext context) {
        Map<String, Object> metadata = context != null ? context.getMetadata() : null;
        if (metadata == null) {
            return Settings.DEFAULTS;
        }
        Integer allowance = integer(metadata.get(ExecutionContext.ANTHROPIC_THINKING_ALLOWANCE_TOKENS));
        return new Settings(
                AnthropicThinkingMode.from(metadata.get(ExecutionContext.ANTHROPIC_THINKING)),
                AnthropicEffort.from(metadata.get(ExecutionContext.ANTHROPIC_EFFORT)),
                integer(metadata.get(ExecutionContext.ANTHROPIC_THINKING_BUDGET_TOKENS)),
                allowance != null && allowance > 0 ? allowance : 0);
    }

    /**
     * The options with the thinking the layer asks for as far as the model takes it and Spring AI can send it, the
     * provider's refusals for the model left out, and the output limit raised by the thinking budget or allowance; the
     * options are a copy the caller made for this call.
     */
    static ChatOptions apply(ChatOptions options, ExecutionContext context, ChatModel selectedModel, String modelName) {
        if (options == null || context == null) {
            return options;
        }
        RECORD_KEYS.forEach(context.getMetadata()::remove);
        Settings settings = settingsOf(context);
        String model = firstNonBlank(readString(options, "getModel"), modelName);
        AnthropicThinkingCapability capability = AnthropicThinkingRules.capabilityOf(model);
        Set<String> resend = resendGroups(context);
        Set<String> refused = new LinkedHashSet<>(refusedGroups(model));
        refused.addAll(resend);
        List<String> adjustments = new ArrayList<>();
        List<String> rejectedFields = new ArrayList<>();

        Thinking wanted = layerThinking(settings, capability, adjustments);
        AnthropicEffort effort = settings.effort();
        if (effort != null && capability != null && !capability.getEffortLevels().contains(effort)) {
            adjustments.add(EFFORT_NOT_SUPPORTED);
            effort = null;
        }
        if (effort != null && wanted != null && (DISABLED.equals(wanted.type()) || BETWEEN_TOOLS.equals(wanted.type()))
                && capability != null && capability.getOffMaxEffort() != null
                && effort.ordinal() > capability.getOffMaxEffort().ordinal()) {
            // D-2: thinking off and an effort the model does not take with it; both are left out (the model default).
            adjustments.add(OFF_WITH_EFFORT_NOT_ACCEPTED);
            wanted = null;
            effort = null;
        }

        ChatOptions result = options;
        Thinking springDefault = thinkingOf(result);
        if (refused.contains(THINKING) && (wanted != null || springDefault != null)) {
            adjustments.add(resend.contains(THINKING)
                    ? PROVIDER_REJECTED_RESENT_WITHOUT_THINKING : PROVIDER_REJECTED_EARLIER_LEFT_OUT);
            rejectedFields.add(THINKING);
            wanted = null;
            springDefault = null;
            setThinking(result, null);
        }
        if (wanted != null && !AnthropicThinkingRules.thinkingTypeExpressible(wanted.type())) {
            adjustments.add(NOT_EXPRESSIBLE_SPRING_AI_1_1);
            wanted = null;
        }
        if (effort != null) {
            // Spring AI 1.1 options carry no output_config.effort; the start refuses an effort setting (D-1).
            addOnce(adjustments, NOT_EXPRESSIBLE_SPRING_AI_1_1);
        }

        Thinking sent;
        String source;
        if (wanted != null) {
            ChatOptions anthropic = anthropicOptions(result);
            if (anthropic != null && setThinking(anthropic, wanted)) {
                result = anthropic;
                sent = wanted;
                source = SOURCE_LAYER_SETTING;
            } else {
                addOnce(adjustments, NOT_EXPRESSIBLE_SPRING_AI_1_1);
                sent = springDefault;
                source = springDefault != null ? SOURCE_SPRING_AI_DEFAULT_OPTIONS : SOURCE_MODEL_DEFAULT;
            }
        } else {
            sent = springDefault;
            source = springDefault != null ? SOURCE_SPRING_AI_DEFAULT_OPTIONS : SOURCE_MODEL_DEFAULT;
        }

        if (refused.contains(SAMPLING) && hasSampling(result)) {
            adjustments.add(resend.contains(SAMPLING)
                    ? PROVIDER_REJECTED_RESENT_WITHOUT_SAMPLING : PROVIDER_REJECTED_EARLIER_LEFT_OUT);
            rejectedFields.addAll(samplingFields(result));
            clearSampling(result, true);
        }
        if (sent != null && ENABLED.equals(sent.type()) && !ProviderAwareChatOptionsFactory.anthropicUsesDefaultSamplingOnly(model)) {
            // The older models take no temperature or top-k with thinking on, and a top-p of 0.95 to 1 only.
            clearSampling(result, false);
            ChatOptions defaults = ProviderAwareChatOptionsFactory.mutableDefaultOptions(selectedModel);
            if (sameModel(defaults, model)) {
                clearSampling(defaults, false);
            }
        }

        Integer answerLimit = result.getMaxTokens();
        int extra = thinkingTokens(sent, settings, capability, rejectedFields.contains(THINKING));
        if (answerLimit != null && extra > 0) {
            invokeSetter(result, "setMaxTokens", Integer.class, answerLimit + extra);
        }
        record(context, settings, sent, source, adjustments, rejectedFields, result, model);
        return result;
    }

    /** What the layer setting asks for the model, with the reason when the model does not take it. */
    private static Thinking layerThinking(Settings settings, AnthropicThinkingCapability capability,
                                          List<String> adjustments) {
        switch (settings.mode()) {
            case OFF -> {
                if (capability == null || capability.getOff() == AnthropicThinkingCapability.Off.DISABLED) {
                    return new Thinking(DISABLED, null);
                }
                if (capability.getOff() == AnthropicThinkingCapability.Off.BETWEEN_TOOLS) {
                    return new Thinking(BETWEEN_TOOLS, null);
                }
                adjustments.add(OFF_NOT_POSSIBLE_ALWAYS_ON);
                return null;
            }
            case ADAPTIVE -> {
                if (capability == null || capability.isAdaptive()) {
                    return new Thinking(ADAPTIVE, null);
                }
                adjustments.add(ADAPTIVE_NOT_ACCEPTED_BY_MODEL);
                return null;
            }
            case BUDGET -> {
                Integer budget = settings.budgetTokens();
                if (budget == null || budget < AnthropicThinkingRules.MIN_BUDGET_TOKENS) {
                    adjustments.add(BUDGET_TOKENS_NOT_VALID);
                    return null;
                }
                if (capability != null && capability.getBudget() == AnthropicThinkingCapability.Budget.REFUSED) {
                    adjustments.add(BUDGET_NOT_ACCEPTED_BY_MODEL);
                    return null;
                }
                return new Thinking(ENABLED, budget);
            }
            default -> {
                return null;
            }
        }
    }

    /**
     * The tokens the output limit adds to the answer limit: the budget of thinking sent with one, none for thinking
     * off, and the allowance when the model thinks without a budget (a thinking type without one, or no thinking field
     * on a model that thinks by default or that refused the field, whose default is then unknown).
     */
    private static int thinkingTokens(Thinking sent, Settings settings, AnthropicThinkingCapability capability,
                                      boolean thinkingRefused) {
        if (sent != null) {
            if (DISABLED.equals(sent.type())) {
                return 0;
            }
            return sent.budgetTokens() != null ? sent.budgetTokens() : settings.allowanceTokens();
        }
        boolean thinksByDefault = capability != null ? capability.thinksByDefault() : thinkingRefused;
        return thinksByDefault ? settings.allowanceTokens() : 0;
    }

    private static void record(ExecutionContext context, Settings settings, Thinking sent, String source,
                               List<String> adjustments, List<String> rejectedFields, ChatOptions options,
                               String model) {
        if (context.getMetadata().containsKey(ExecutionContext.ANTHROPIC_THINKING)) {
            context.addMetadata(ExecutionContext.PROVIDER_THINKING_REQUESTED, settings.mode().name());
        }
        if (settings.effort() != null) {
            context.addMetadata(ExecutionContext.PROVIDER_EFFORT_REQUESTED, settings.effort().name());
        }
        context.addMetadata(ExecutionContext.PROVIDER_THINKING,
                sent != null ? sent.type().toUpperCase(Locale.ROOT) : "ABSENT");
        if (sent != null && sent.budgetTokens() != null) {
            context.addMetadata(ExecutionContext.PROVIDER_THINKING_BUDGET_TOKENS, sent.budgetTokens());
        }
        context.addMetadata(ExecutionContext.PROVIDER_THINKING_SOURCE, source);
        if (!adjustments.isEmpty()) {
            context.addMetadata(ExecutionContext.PROVIDER_THINKING_ADJUSTMENT, List.copyOf(adjustments));
        }
        if (!rejectedFields.isEmpty()) {
            context.addMetadata(ExecutionContext.PROVIDER_REJECTED_FIELDS, List.copyOf(rejectedFields));
        }
        if (options.getMaxTokens() != null) {
            context.addMetadata(ExecutionContext.PROVIDER_MAX_TOKENS_SENT, options.getMaxTokens());
        }
        List<String> sentFields = new ArrayList<>();
        if (sent != null) {
            sentFields.add(THINKING);
        }
        sentFields.addAll(samplingFields(options));
        if (model != null) {
            context.addMetadata(REQUEST_MODEL, model);
        }
        context.addMetadata(SENT_FIELDS, List.copyOf(sentFields));
    }

    /**
     * The field groups of the call's request that the provider's refusal names: thinking (with its budget_tokens) and
     * sampling (temperature, top_p, top_k), each only when the request carried it; empty when it names none.
     */
    static Set<String> refusedFieldGroups(ExecutionContext context, String errorText) {
        Object sent = context != null ? context.getMetadata().get(SENT_FIELDS) : null;
        if (!(sent instanceof List<?> fields) || fields.isEmpty() || errorText == null) {
            return Set.of();
        }
        String text = errorText.toLowerCase(Locale.ROOT);
        Set<String> groups = new LinkedHashSet<>();
        if (fields.contains(THINKING) && (text.contains("thinking") || text.contains("budget_tokens"))) {
            groups.add(THINKING);
        }
        boolean samplingSent = fields.stream().anyMatch(SAMPLING_FIELDS::contains);
        if (samplingSent && SAMPLING_FIELDS.stream().anyMatch(text::contains)) {
            groups.add(SAMPLING);
        }
        return groups;
    }

    /**
     * Starts the one resend without the refused groups: they count as refused for the model while it is in flight and
     * leave the model's default options in place (so the request carries none of them), and the call notes them.
     */
    static Resend beginResend(ExecutionContext context, ChatModel selectedModel, Set<String> groups) {
        String model = context != null ? text(context.getMetadata().get(REQUEST_MODEL)) : null;
        Set<String> registered = new LinkedHashSet<>();
        if (model != null) {
            Set<String> modelRefusals = REFUSED.computeIfAbsent(key(model), ignored -> ConcurrentHashMap.newKeySet());
            for (String group : groups) {
                if (modelRefusals.add(group)) {
                    registered.add(group);
                }
            }
        }
        Map<String, Object> removed = removeRefusedInPlace(ProviderAwareChatOptionsFactory.mutableDefaultOptions(selectedModel));
        if (context != null) {
            context.addMetadata(RESEND_GROUPS, Set.copyOf(groups));
        }
        return new Resend(model, Set.copyOf(groups), registered, removed);
    }

    /** The resend was answered: the refusal stays for the model's later calls, logged once per model and group. */
    static void confirmResend(Resend resend, String providerMessage) {
        for (String group : resend.groups()) {
            if (LOGGED.add(key(resend.model()) + "|" + group)) {
                log.error("[AnthropicThinking] The provider refused the {} field of model {} ({}); the request was sent"
                                + " once more without it, and the field is left out of this model's requests from now on.",
                        group, resend.model(), providerMessage);
            }
        }
    }

    /** The resend failed too: nothing is kept, the refusal it registered and the defaults it took out are restored. */
    static void abandonResend(ChatModel selectedModel, Resend resend) {
        if (resend.model() != null) {
            Set<String> modelRefusals = REFUSED.get(key(resend.model()));
            if (modelRefusals != null) {
                modelRefusals.removeAll(resend.registered());
            }
        }
        ChatOptions defaults = ProviderAwareChatOptionsFactory.mutableDefaultOptions(selectedModel);
        if (defaults == null) {
            return;
        }
        resend.removedDefaults().forEach((field, value) -> {
            switch (field) {
                case THINKING -> {
                    if (thinkingOf(defaults) == null) {
                        invokeSetter(defaults, "setThinking", value.getClass(), value);
                    }
                }
                case "temperature" -> {
                    if (defaults.getTemperature() == null) {
                        invokeSetter(defaults, "setTemperature", Double.class, value);
                    }
                }
                case "top_p" -> {
                    if (defaults.getTopP() == null) {
                        invokeSetter(defaults, "setTopP", Double.class, value);
                    }
                }
                case "top_k" -> {
                    if (defaults.getTopK() == null) {
                        invokeSetter(defaults, "setTopK", Integer.class, value);
                    }
                }
                default -> {
                }
            }
        });
    }

    /**
     * Takes the fields the provider refused for the defaults' model out of the default options in place, returning
     * what it took out; other models' defaults stay as they are.
     */
    static Map<String, Object> removeRefusedInPlace(ChatOptions defaults) {
        String model = readString(defaults, "getModel");
        Set<String> groups = model != null ? REFUSED.get(key(model)) : null;
        if (groups == null || groups.isEmpty() || !isAnthropicOptions(defaults)) {
            return Map.of();
        }
        Map<String, Object> removed = new LinkedHashMap<>();
        if (groups.contains(THINKING)) {
            Object thinking = invokeGetter(defaults, "getThinking");
            if (thinking != null) {
                removed.put(THINKING, thinking);
                setThinking(defaults, null);
            }
        }
        if (groups.contains(SAMPLING)) {
            putIfPresent(removed, "temperature", defaults.getTemperature());
            putIfPresent(removed, "top_p", defaults.getTopP());
            putIfPresent(removed, "top_k", defaults.getTopK());
            clearSampling(defaults, true);
        }
        return removed;
    }

    private static Set<String> resendGroups(ExecutionContext context) {
        Object groups = context.getMetadata().get(RESEND_GROUPS);
        if (!(groups instanceof Set<?> set)) {
            return Set.of();
        }
        Set<String> result = new LinkedHashSet<>();
        set.forEach(group -> result.add(String.valueOf(group)));
        return result;
    }

    private static Set<String> refusedGroups(String model) {
        Set<String> groups = model != null ? REFUSED.get(key(model)) : null;
        return groups != null ? groups : Set.of();
    }

    private static boolean sameModel(ChatOptions defaults, String model) {
        String defaultsModel = readString(defaults, "getModel");
        return model != null && defaultsModel != null && defaultsModel.equalsIgnoreCase(model)
                && isAnthropicOptions(defaults);
    }

    private static List<String> samplingFields(ChatOptions options) {
        List<String> fields = new ArrayList<>();
        if (options.getTemperature() != null) {
            fields.add("temperature");
        }
        if (options.getTopP() != null) {
            fields.add("top_p");
        }
        if (options.getTopK() != null) {
            fields.add("top_k");
        }
        return fields;
    }

    private static boolean hasSampling(ChatOptions options) {
        return !samplingFields(options).isEmpty();
    }

    /** Takes out every sampling value, or with thinking on an older model those it refuses (top-p of 0.95 to 1 stays). */
    private static void clearSampling(ChatOptions options, boolean all) {
        if (options == null) {
            return;
        }
        Double topP = options.getTopP();
        invokeSetter(options, "setTemperature", Double.class, null);
        invokeSetter(options, "setTopK", Integer.class, null);
        if (all || (topP != null && (topP < 0.95d || topP > 1.0d))) {
            invokeSetter(options, "setTopP", Double.class, null);
        }
    }

    /** The thinking the options carry; null for none. */
    private static Thinking thinkingOf(ChatOptions options) {
        Object thinking = invokeGetter(options, "getThinking");
        if (thinking == null) {
            return null;
        }
        Object type = invokeGetter(thinking, "type");
        Object budget = invokeGetter(thinking, "budgetTokens");
        String typeName = type instanceof Enum<?> constant ? constant.name().toLowerCase(Locale.ROOT)
                : type != null ? type.toString().toLowerCase(Locale.ROOT) : null;
        return typeName != null ? new Thinking(typeName, budget instanceof Integer tokens ? tokens : null) : null;
    }

    /** Sets the thinking on Anthropic options, or takes it out for null; false when the type cannot be sent. */
    private static boolean setThinking(ChatOptions options, Thinking thinking) {
        if (!isAnthropicOptions(options)) {
            return thinking == null;
        }
        try {
            Class<?> configClass = Class.forName(AnthropicThinkingRules.THINKING_CONFIG_CLASS);
            Object config = null;
            if (thinking != null) {
                Class<?> typeClass = Class.forName(AnthropicThinkingRules.THINKING_TYPE_CLASS);
                Object type = null;
                for (Object constant : typeClass.getEnumConstants()) {
                    if (((Enum<?>) constant).name().replace("_", "")
                            .equalsIgnoreCase(thinking.type().replace("_", ""))) {
                        type = constant;
                    }
                }
                if (type == null) {
                    return false;
                }
                config = configClass.getConstructor(typeClass, Integer.class).newInstance(type, thinking.budgetTokens());
            }
            options.getClass().getMethod("setThinking", configClass).invoke(options, config);
            return true;
        } catch (ReflectiveOperationException | LinkageError ex) {
            return false;
        }
    }

    /** Anthropic options of the same values, so a thinking field can be set; null without Anthropic on the class path. */
    @SuppressWarnings("unchecked")
    private static ChatOptions anthropicOptions(ChatOptions options) {
        if (isAnthropicOptions(options)) {
            return options;
        }
        try {
            Class<? extends ChatOptions> anthropic = (Class<? extends ChatOptions>)
                    Class.forName(AnthropicThinkingRules.ANTHROPIC_CHAT_OPTIONS_CLASS);
            return ModelOptionsUtils.copyToTarget(options, ChatOptions.class, anthropic);
        } catch (ClassNotFoundException | LinkageError | RuntimeException ex) {
            return null;
        }
    }

    private static boolean isAnthropicOptions(Object options) {
        return options != null && options.getClass().getName().equals(AnthropicThinkingRules.ANTHROPIC_CHAT_OPTIONS_CLASS);
    }

    private static void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private static void addOnce(List<String> values, String value) {
        if (!values.contains(value)) {
            values.add(value);
        }
    }

    private static String key(String model) {
        return model != null ? model.trim().toLowerCase(Locale.ROOT) : "";
    }

    private static Integer integer(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Integer.parseInt(text.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static String text(Object value) {
        String text = value != null ? value.toString().trim() : "";
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

    private static String readString(Object target, String method) {
        return text(invokeGetter(target, method));
    }

    private static Object invokeGetter(Object target, String method) {
        if (target == null) {
            return null;
        }
        try {
            Method getter = target.getClass().getMethod(method);
            return getter.invoke(target);
        } catch (ReflectiveOperationException | RuntimeException ex) {
            return null;
        }
    }

    /** Sets an option; options without the setter keep their value, so the call goes out as it would have. */
    private static void invokeSetter(Object target, String method, Class<?> type, Object value) {
        try {
            target.getClass().getMethod(method, type).invoke(target, value);
        } catch (ReflectiveOperationException | RuntimeException ex) {
            log.error("[AnthropicThinking] Cannot set chat option {} on {}", method, target.getClass().getName(), ex);
        }
    }
}
