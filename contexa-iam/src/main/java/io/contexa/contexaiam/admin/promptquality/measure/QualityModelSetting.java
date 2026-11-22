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
package io.contexa.contexaiam.admin.promptquality.measure;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayInputs;
import org.springframework.lang.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The model setting of a measurement (quality plan 3.3): the server settings that change an answer, before the
 * measurement runs, and the models that answered, after it. Two measurements are compared only when the two are the
 * same. The settings are the models each layer asks (its own, else the primary chat model's), the options of each
 * layer's request (output limit, reasoning effort, verbosity, thinking, budget profile), the determinism of the call,
 * the structured output, the prompt's truncation and argument excerpts, the minimum-action rules and their mode, what
 * an ESCALATE left after the second pass ends in and the context format the cases are read in. Timeouts, caches and the
 * gate change whether an answer comes, not which, so they are not in it; nor is the time zone of the server, since a
 * case is drawn in the time zone it fixes (quality plan 3.2) and that time zone is part of the case's content.
 */
public final class QualityModelSetting {

    /** The setting of the model the first layer asks. */
    public static final String FIRST_MODEL = "layer1.model";
    /** The setting of the model the second layer asks. */
    public static final String SECOND_MODEL = "layer2.model";

    private QualityModelSetting() {
    }

    /** The settings of the server that change an answer, by a stable name, with no primary chat model known. */
    public static Map<String, String> settings(@Nullable TieredStrategyProperties tiered,
                                               @Nullable TieredLLMProperties models,
                                               @Nullable SecurityZeroTrustProperties zeroTrust) {
        return settings(tiered, models, zeroTrust, null);
    }

    /**
     * The settings of the server that change an answer, by a stable name.
     *
     * @param defaultModel the model of the primary chat model, which a layer with no model of its own asks (K196: the
     *                     model that answers is named, not the absence of a layer's own); null when it names none
     */
    public static Map<String, String> settings(@Nullable TieredStrategyProperties tiered,
                                               @Nullable TieredLLMProperties models,
                                               @Nullable SecurityZeroTrustProperties zeroTrust,
                                               @Nullable String defaultModel) {
        TieredStrategyProperties strategy = tiered != null ? tiered : new TieredStrategyProperties();
        Map<String, String> settings = new TreeMap<>();
        putModel(settings, FIRST_MODEL, models != null ? models.getModelNameForTier(1) : null, defaultModel);
        putModel(settings, SECOND_MODEL, models != null ? models.getModelNameForTier(2) : null, defaultModel);
        if (models != null) {
            settings.put("layer1.backupModel", String.valueOf(models.getBackupModelNameForTier(1)));
            settings.put("layer2.backupModel", String.valueOf(models.getBackupModelNameForTier(2)));
        }
        TieredStrategyProperties.Layer1 first = strategy.getLayer1();
        settings.put("layer1.maxOutputTokens", String.valueOf(first.getMaxOutputTokens()));
        settings.put("layer1.openAiReasoningEffort", String.valueOf(first.getOpenAiReasoningEffort()));
        settings.put("layer1.openAiVerbosity", String.valueOf(first.getOpenAiVerbosity()));
        settings.put("layer1.anthropicThinking", String.valueOf(first.getAnthropicThinking()));
        settings.put("layer1.anthropicEffort", String.valueOf(first.getAnthropicEffort()));
        settings.put("layer1.anthropicThinkingBudgetTokens", String.valueOf(first.getAnthropicThinkingBudgetTokens()));
        settings.put("layer1.anthropicThinkingAllowanceTokens",
                String.valueOf(first.getAnthropicThinkingAllowanceTokens()));
        settings.put("layer1.defaultBudgetProfile", String.valueOf(first.getDefaultBudgetProfile()));
        TieredStrategyProperties.Layer2 second = strategy.getLayer2();
        settings.put("layer2.maxOutputTokens", String.valueOf(second.getMaxOutputTokens()));
        settings.put("layer2.openAiReasoningEffort", String.valueOf(second.getOpenAiReasoningEffort()));
        settings.put("layer2.openAiVerbosity", String.valueOf(second.getOpenAiVerbosity()));
        settings.put("layer2.anthropicThinking", String.valueOf(second.getAnthropicThinking()));
        settings.put("layer2.anthropicEffort", String.valueOf(second.getAnthropicEffort()));
        settings.put("layer2.anthropicThinkingBudgetTokens", String.valueOf(second.getAnthropicThinkingBudgetTokens()));
        settings.put("layer2.anthropicThinkingAllowanceTokens",
                String.valueOf(second.getAnthropicThinkingAllowanceTokens()));
        settings.put("layer2.defaultBudgetProfile", String.valueOf(second.getDefaultBudgetProfile()));
        settings.put("layer2.escalateTerminalAction", String.valueOf(second.escalateTerminalAction()));
        settings.put("determinism", String.valueOf(strategy.getDeterminism()));
        settings.put("promptRuntime.nativeStructuredOutputEnabled",
                String.valueOf(strategy.getPromptRuntime().isNativeStructuredOutputEnabled()));
        settings.put("promptRuntime.nativeStructuredOutputDisabledProfiles",
                String.valueOf(strategy.getPromptRuntime().getNativeStructuredOutputDisabledProfiles()));
        settings.put("promptRuntime.budgetEnforcement",
                String.valueOf(strategy.getPromptRuntime().getBudgetEnforcement()));
        settings.put("truncation", String.valueOf(strategy.getTruncation()));
        settings.put("argumentOrigin", String.valueOf(strategy.getArgumentOrigin()));
        if (zeroTrust != null && zeroTrust.getMinimumAction() != null) {
            settings.put("minimumAction.mode", String.valueOf(zeroTrust.getMinimumAction().getMode()));
            settings.put("minimumAction.rules", String.valueOf(zeroTrust.getMinimumAction().toRules()));
        }
        settings.put("contextFormat", SealedDecisionReplayInputs.CONTEXT_FORMAT_VERSION);
        return settings;
    }

    /** The model a layer asks: its own, else the primary chat model's; left out when neither is named. */
    private static void putModel(Map<String, String> settings, String name, @Nullable String own,
                                 @Nullable String defaultModel) {
        String model = own != null && !own.isBlank() ? own.trim()
                : defaultModel != null && !defaultModel.isBlank() ? defaultModel.trim() : null;
        if (model != null) {
            settings.put(name, model);
        }
    }

    /** The closing rules the server's settings give: what an ESCALATE left after the second pass ends in. */
    public static QualityClosingRules closingRules(@Nullable TieredStrategyProperties tiered) {
        TieredStrategyProperties strategy = tiered != null ? tiered : new TieredStrategyProperties();
        Object terminal = strategy.getLayer2().escalateTerminalAction();
        return new QualityClosingRules(terminal != null ? QualityAction.parse(String.valueOf(terminal)) : null);
    }

    /**
     * Quality plan 3.6: the settings that differ between two, by name, each with its value before and after (null
     * where one has none), in the order of the names.
     */
    public static Map<String, List<String>> changed(Map<String, String> before, Map<String, String> after) {
        Map<String, List<String>> changed = new TreeMap<>();
        TreeSet<String> names = new TreeSet<>(before.keySet());
        names.addAll(after.keySet());
        for (String name : names) {
            String was = before.get(name);
            String now = after.get(name);
            if (!Objects.equals(was, now)) {
                changed.put(name, Arrays.asList(was, now));
            }
        }
        return changed;
    }

    /** The hash of the settings: the same settings in any order give the same hash. */
    public static String hash(Map<String, String> settings) {
        StringBuilder text = new StringBuilder();
        new TreeMap<>(Objects.requireNonNull(settings, "settings")).forEach((name, value) ->
                text.append(name.length()).append(':').append(name).append('=').append(value == null ? 0
                        : value.length()).append(':').append(value).append('\n'));
        return sha256(text.toString());
    }

    /**
     * The model setting a measurement names: the hash of the settings and the models that answered it, so that a
     * fallback model or a model changed on the provider's side makes another setting.
     */
    public static String fingerprint(String settingsHash, Collection<String> answeredModels) {
        TreeSet<String> models = new TreeSet<>();
        if (answeredModels != null) {
            answeredModels.stream().filter(Objects::nonNull).map(String::trim).filter(model -> !model.isEmpty())
                    .forEach(models::add);
        }
        return "settings=" + settingsHash + ";models=" + (models.isEmpty() ? "unknown" : String.join(",", models));
    }

    static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 algorithm is not available.", exception);
        }
    }
}
