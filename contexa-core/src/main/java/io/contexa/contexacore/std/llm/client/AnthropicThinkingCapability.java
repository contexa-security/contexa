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
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * One row of the Anthropic thinking capability table ({@code contexa.llm.model-capabilities.anthropic.thinking}): the
 * Claude models a pattern names and what they take of thinking and effort. The rows are read top down and the first
 * whose pattern matches the whole model id applies; a model no row names gets what the layer asks as it is, and a 400
 * for a thinking, effort or sampling field is then sent once more without it. The default rows are the Claude API's
 * thinking troubleshooting and effort tables as read on 2026-10-30; a host may replace them.
 */
@Slf4j
@Data
@NoArgsConstructor
public class AnthropicThinkingCapability {

    /** What thinking off is for a model. */
    public enum Off {
        /** {@code thinking.type: disabled}. */
        DISABLED,
        /** {@code thinking.type: between_tools} (Claude Sonnet 5.5); Spring AI 1.1 cannot send it. */
        BETWEEN_TOOLS,
        /** The model always thinks and refuses every way of turning it off. */
        NOT_POSSIBLE
    }

    /** Whether a model takes {@code thinking.type: enabled} with {@code budget_tokens}. */
    public enum Budget {
        ACCEPTED,
        /** Taken, but deprecated for the model. */
        DEPRECATED,
        /** Refused with a 400. */
        REFUSED
    }

    /** How a model thinks when the request carries no thinking field. */
    public enum DefaultThinking {
        ALWAYS_ON,
        ON,
        OFF
    }

    private static final Map<String, Pattern> COMPILED = new ConcurrentHashMap<>();

    /** A regular expression the whole model id matches, ignoring case. */
    private String pattern;

    /** Whether the model takes {@code thinking.type: adaptive}. */
    private boolean adaptive;

    /** What thinking off is for the model. */
    private Off off = Off.DISABLED;

    /** The highest effort the model takes with thinking off; empty for no limit. */
    private AnthropicEffort offMaxEffort;

    /** Whether the model takes a thinking budget. */
    private Budget budget = Budget.ACCEPTED;

    /** The effort levels the model takes; empty when it takes no effort. */
    private List<AnthropicEffort> effortLevels = new ArrayList<>();

    /** How the model thinks when the request carries no thinking field. */
    private DefaultThinking defaultThinking = DefaultThinking.OFF;

    public AnthropicThinkingCapability(String pattern, boolean adaptive, Off off, AnthropicEffort offMaxEffort,
                                       Budget budget, List<AnthropicEffort> effortLevels,
                                       DefaultThinking defaultThinking) {
        this.pattern = pattern;
        this.adaptive = adaptive;
        this.off = off;
        this.offMaxEffort = offMaxEffort;
        this.budget = budget;
        this.effortLevels = new ArrayList<>(effortLevels);
        this.defaultThinking = defaultThinking;
    }

    /** Whether the row's pattern matches the whole model id; a pattern that does not compile matches none. */
    public boolean matches(String modelId) {
        if (modelId == null || modelId.isBlank() || pattern == null || pattern.isBlank()) {
            return false;
        }
        try {
            Pattern compiled = COMPILED.computeIfAbsent(pattern.trim(),
                    text -> Pattern.compile(text, Pattern.CASE_INSENSITIVE));
            return compiled.matcher(modelId.trim()).matches();
        } catch (PatternSyntaxException ex) {
            log.error("Ignoring invalid Anthropic thinking capability pattern '{}'", pattern);
            return false;
        }
    }

    /** Whether the model thinks when the request carries no thinking field. */
    public boolean thinksByDefault() {
        return defaultThinking != DefaultThinking.OFF;
    }

    /**
     * The Claude API's table (thinking troubleshooting and effort pages, read 2026-10-30), newest first. A model id is
     * the API's id with an optional date or version suffix ({@code -20251101}, {@code @20251101}).
     */
    public static List<AnthropicThinkingCapability> officialTable() {
        List<AnthropicEffort> all = List.of(AnthropicEffort.values());
        List<AnthropicEffort> noXhigh = List.of(AnthropicEffort.LOW, AnthropicEffort.MEDIUM, AnthropicEffort.HIGH,
                AnthropicEffort.MAX);
        List<AnthropicEffort> upToHigh = List.of(AnthropicEffort.LOW, AnthropicEffort.MEDIUM, AnthropicEffort.HIGH);
        return List.of(
                // Fable 5.1, Mythos 5.1, Fable 5, Mythos 5, Opus 5.5: adaptive only, always on.
                new AnthropicThinkingCapability(
                        "claude-(?:fable|mythos)-5-1(?:[-@].*)?|claude-(?:fable|mythos)-5(?:[-@]\\d{8})?"
                                + "|claude-opus-5-5(?:[-@].*)?",
                        true, Off.NOT_POSSIBLE, null, Budget.REFUSED, all, DefaultThinking.ALWAYS_ON),
                // Mythos Preview: adaptive and extended, always on; no xhigh.
                new AnthropicThinkingCapability("claude-mythos-preview(?:[-@].*)?",
                        true, Off.NOT_POSSIBLE, null, Budget.ACCEPTED, noXhigh, DefaultThinking.ALWAYS_ON),
                // Opus 5: adaptive only, on; disabled only at effort high or below.
                new AnthropicThinkingCapability("claude-opus-5(?:[-@]\\d{8})?",
                        true, Off.DISABLED, AnthropicEffort.HIGH, Budget.REFUSED, all, DefaultThinking.ON),
                // Sonnet 5.5: adaptive and between_tools (its way of thinking off, effort high or below), on.
                new AnthropicThinkingCapability("claude-sonnet-5-5(?:[-@].*)?",
                        true, Off.BETWEEN_TOOLS, AnthropicEffort.HIGH, Budget.REFUSED, all, DefaultThinking.ON),
                // Sonnet 5: adaptive only, on.
                new AnthropicThinkingCapability("claude-sonnet-5(?:[-@]\\d{8})?",
                        true, Off.DISABLED, null, Budget.REFUSED, all, DefaultThinking.ON),
                // Haiku 5.5: adaptive only, on; disabled only at effort high or below.
                new AnthropicThinkingCapability("claude-haiku-5-5(?:[-@].*)?",
                        true, Off.DISABLED, AnthropicEffort.HIGH, Budget.REFUSED, all, DefaultThinking.ON),
                // Opus 4.8 and 4.7: adaptive only, off.
                new AnthropicThinkingCapability("claude-opus-4-[78](?:[-@].*)?",
                        true, Off.DISABLED, null, Budget.REFUSED, all, DefaultThinking.OFF),
                // Opus 4.6 and Sonnet 4.6: adaptive and extended (deprecated), off; no xhigh.
                new AnthropicThinkingCapability("claude-(?:opus|sonnet)-4-6(?:[-@].*)?",
                        true, Off.DISABLED, null, Budget.DEPRECATED, noXhigh, DefaultThinking.OFF),
                // Opus 4.5: extended only, off; effort without xhigh (max is not in the effort documentation's list).
                new AnthropicThinkingCapability("claude-opus-4-5(?:[-@].*)?",
                        false, Off.DISABLED, null, Budget.ACCEPTED, upToHigh, DefaultThinking.OFF),
                // Haiku 4.5, Sonnet 4.5 and the earlier Claude 4 models: extended only, off, no effort.
                new AnthropicThinkingCapability("claude-(?:haiku|sonnet)-4-5(?:[-@].*)?|claude-opus-4-1(?:[-@].*)?"
                        + "|claude-(?:opus|sonnet)-4(?:-0)?(?:[-@]\\d{8})?",
                        false, Off.DISABLED, null, Budget.ACCEPTED, List.of(), DefaultThinking.OFF));
    }
}
