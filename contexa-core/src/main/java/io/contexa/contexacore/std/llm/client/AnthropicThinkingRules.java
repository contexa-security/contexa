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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The rules of the Anthropic thinking settings of a security decision layer: the capability table a model is read
 * against, what Spring AI on the class path can send, and the settings a known layer model contradicts, refused or
 * warned about when the application starts. Contexa picks no value: a refusal names the setting and the Claude API
 * rule it breaks, and the host chooses what to set instead.
 */
public final class AnthropicThinkingRules {

    /** The smallest thinking budget the Claude API takes (extended thinking documentation). */
    public static final int MIN_BUDGET_TOKENS = 1024;

    static final String ANTHROPIC_API_CLASS = "org.springframework.ai.anthropic.api.AnthropicApi";
    static final String THINKING_TYPE_CLASS = ANTHROPIC_API_CLASS + "$ThinkingType";
    static final String THINKING_CONFIG_CLASS = ANTHROPIC_API_CLASS + "$ChatCompletionRequest$ThinkingConfig";
    static final String ANTHROPIC_CHAT_OPTIONS_CLASS = "org.springframework.ai.anthropic.AnthropicChatOptions";

    private static final AtomicReference<List<AnthropicThinkingCapability>> CAPABILITIES =
            new AtomicReference<>(AnthropicThinkingCapability.officialTable());

    private AnthropicThinkingRules() {
    }

    /** The settings of one layer as the strategy passes them to the model call. */
    public record Settings(AnthropicThinkingMode mode, AnthropicEffort effort, Integer budgetTokens,
                           int allowanceTokens) {

        public static final Settings DEFAULTS = new Settings(AnthropicThinkingMode.PROVIDER_DEFAULT, null, null, 0);

        public Settings {
            mode = mode != null ? mode : AnthropicThinkingMode.PROVIDER_DEFAULT;
        }
    }

    /** What the application start finds: the settings it refuses and the ones it warns about. */
    public record Findings(List<String> refusals, List<String> warnings) {

        public Findings {
            refusals = List.copyOf(refusals);
            warnings = List.copyOf(warnings);
        }
    }

    /** The capability table, top down; null or empty restores the Claude API's table. */
    public static void configureCapabilities(List<AnthropicThinkingCapability> capabilities) {
        CAPABILITIES.set(capabilities == null || capabilities.isEmpty()
                ? AnthropicThinkingCapability.officialTable()
                : List.copyOf(capabilities));
    }

    /** The first row whose pattern matches the whole model id; null when none does. */
    public static AnthropicThinkingCapability capabilityOf(String modelId) {
        for (AnthropicThinkingCapability capability : CAPABILITIES.get()) {
            if (capability != null && capability.matches(modelId)) {
                return capability;
            }
        }
        return null;
    }

    /**
     * Whether the Spring AI Anthropic options on the class path have a thinking type of this name ("disabled",
     * "enabled", "adaptive", "between_tools"); Spring AI 1.1 has enabled and disabled only.
     */
    public static boolean thinkingTypeExpressible(String type) {
        try {
            Class<?> thinkingType = Class.forName(THINKING_TYPE_CLASS);
            Class.forName(THINKING_CONFIG_CLASS);
            String wanted = type.replace("_", "").toUpperCase(Locale.ROOT);
            return thinkingType.isEnum()
                    && Arrays.stream(thinkingType.getEnumConstants())
                    .anyMatch(constant -> ((Enum<?>) constant).name().replace("_", "").equals(wanted));
        } catch (ClassNotFoundException | LinkageError ex) {
            return false;
        }
    }

    /** Whether the Spring AI Anthropic options on the class path can carry {@code output_config.effort}. */
    public static boolean effortExpressible() {
        try {
            Class<?> options = Class.forName(ANTHROPIC_CHAT_OPTIONS_CLASS);
            return Arrays.stream(options.getMethods())
                    .anyMatch(method -> method.getName().equals("setEffort") || method.getName().equals("setOutputConfig"));
        } catch (ClassNotFoundException | LinkageError ex) {
            return false;
        }
    }

    /**
     * The settings of one layer checked when the application starts: those the settings alone contradict, and with a
     * known layer model those its capability row contradicts (the Claude API refuses them with a 400). A model no row
     * names is checked on the settings alone; the model call then sends what it can and records what it left out.
     *
     * @param layer the property prefix of the layer, as {@code contexa.security.tiered.layer1}
     * @param settings the layer's Anthropic thinking settings
     * @param answerLimit the layer's {@code max-output-tokens}
     * @param modelId the model the layer runs on when it is known to be a Claude model; null otherwise
     */
    public static Findings check(String layer, Settings settings, int answerLimit, String modelId) {
        List<String> refusals = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        Settings checked = settings != null ? settings : Settings.DEFAULTS;
        AnthropicThinkingMode mode = checked.mode();
        if (checked.allowanceTokens() < 0) {
            refusals.add(layer + ".anthropic-thinking-allowance-tokens must be 0 or more; it is "
                    + checked.allowanceTokens() + ".");
        }
        if (mode == AnthropicThinkingMode.ADAPTIVE && !thinkingTypeExpressible("adaptive")) {
            refusals.add(layer + ".anthropic-thinking=ADAPTIVE cannot be sent with the Spring AI on the class path: "
                    + "Spring AI 1.1 Anthropic options have only the thinking types enabled and disabled. Adaptive "
                    + "thinking needs Spring AI 2.0.x (its Anthropic options take it from 2.0.0).");
        }
        if (checked.effort() != null && !effortExpressible()) {
            refusals.add(layer + ".anthropic-effort=" + checked.effort() + " cannot be sent with the Spring AI on the"
                    + " class path: Spring AI 1.1 Anthropic options have no output_config.effort. The effort needs"
                    + " Spring AI 2.0.x (its Anthropic options take it from 2.0.0); without it, leave anthropic-effort"
                    + " empty.");
        }
        if (mode == AnthropicThinkingMode.BUDGET) {
            Integer budget = checked.budgetTokens();
            if (budget == null || budget < MIN_BUDGET_TOKENS) {
                refusals.add(layer + ".anthropic-thinking=BUDGET needs " + layer + ".anthropic-thinking-budget-tokens"
                        + " of at least " + MIN_BUDGET_TOKENS + " (Claude API extended thinking: budget_tokens is at"
                        + " least 1,024 and less than max_tokens); it is " + (budget != null ? budget : "not set")
                        + ".");
            }
            if (answerLimit <= 0) {
                refusals.add(layer + ".anthropic-thinking=BUDGET needs a positive " + layer + ".max-output-tokens"
                        + " (the answer limit max_tokens adds the budget to); it is " + answerLimit + ".");
            }
        } else if (checked.budgetTokens() != null) {
            warnings.add(layer + ".anthropic-thinking-budget-tokens is set but " + layer + ".anthropic-thinking is "
                    + mode + "; the budget is not used.");
        }
        AnthropicThinkingCapability capability = modelId != null ? capabilityOf(modelId) : null;
        if (capability != null) {
            checkModel(layer, checked, answerLimit, modelId, capability, refusals, warnings);
        }
        return new Findings(refusals, warnings);
    }

    private static void checkModel(String layer, Settings settings, int answerLimit, String modelId,
                                   AnthropicThinkingCapability capability, List<String> refusals,
                                   List<String> warnings) {
        String model = " the layer model " + modelId;
        AnthropicThinkingMode mode = settings.mode();
        AnthropicEffort effort = settings.effort();
        boolean thinkingLeftOut = mode == AnthropicThinkingMode.PROVIDER_DEFAULT;
        if (mode == AnthropicThinkingMode.OFF) {
            if (capability.getOff() == AnthropicThinkingCapability.Off.NOT_POSSIBLE) {
                refusals.add(layer + ".anthropic-thinking=OFF:" + model + " cannot turn thinking off (Claude API"
                        + " thinking troubleshooting: models marked always on refuse every way of turning thinking off"
                        + " with a 400).");
            } else if (capability.getOff() == AnthropicThinkingCapability.Off.BETWEEN_TOOLS
                    && !thinkingTypeExpressible("between_tools")) {
                thinkingLeftOut = true;
                warnings.add(layer + ".anthropic-thinking=OFF:" + model + " turns thinking off with thinking.type"
                        + " between_tools, which the Spring AI on the class path cannot send (it needs Spring AI 2.0.2"
                        + " or later); the thinking field is left out, the model thinks as it does by default, and"
                        + " every decision records NOT_EXPRESSIBLE_SPRING_AI_1_1.");
            }
            if (effort != null && capability.getOffMaxEffort() != null
                    && effort.ordinal() > capability.getOffMaxEffort().ordinal()) {
                refusals.add(layer + ".anthropic-thinking=OFF with anthropic-effort=" + effort + ":" + model
                        + " takes thinking off only at effort " + capability.getOffMaxEffort().wireValue()
                        + " or below (Claude API thinking troubleshooting).");
            }
        }
        if (mode == AnthropicThinkingMode.BUDGET) {
            if (capability.getBudget() == AnthropicThinkingCapability.Budget.REFUSED) {
                refusals.add(layer + ".anthropic-thinking=BUDGET:" + model + " refuses thinking.type enabled with"
                        + " budget_tokens with a 400 (Claude API thinking troubleshooting: this model takes thinking.type"
                        + " adaptive and output_config.effort instead).");
            } else if (capability.getBudget() == AnthropicThinkingCapability.Budget.DEPRECATED) {
                warnings.add(layer + ".anthropic-thinking=BUDGET:" + model + " still takes budget_tokens, which the"
                        + " Claude API documents as deprecated for it.");
            }
        }
        if (mode == AnthropicThinkingMode.ADAPTIVE && !capability.isAdaptive()) {
            refusals.add(layer + ".anthropic-thinking=ADAPTIVE:" + model + " refuses adaptive thinking with a 400"
                    + " (Claude API thinking troubleshooting).");
        }
        if (effort != null && !capability.getEffortLevels().contains(effort)) {
            warnings.add(layer + ".anthropic-effort=" + effort + ":" + model + " does not list this effort level"
                    + " (Claude API effort documentation); the call leaves the effort out.");
        }
        if ((thinkingLeftOut || mode == AnthropicThinkingMode.ADAPTIVE) && capability.thinksByDefault()
                && settings.allowanceTokens() == 0) {
            warnings.add(layer + ":" + model + " thinks by default and its thinking counts against max_tokens ("
                    + layer + ".max-output-tokens " + answerLimit + ") while " + layer
                    + ".anthropic-thinking-allowance-tokens is 0; the longer the input, the more answers are cut."
                    + " Every decision records providerFinishReason and providerMaxTokensSent.");
        }
    }
}
