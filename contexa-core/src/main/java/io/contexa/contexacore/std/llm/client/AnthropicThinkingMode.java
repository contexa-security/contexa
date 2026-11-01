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

import java.util.Locale;

/**
 * The thinking a security decision layer asks of an Anthropic model ({@code contexa.security.tiered.layerN.anthropic-thinking}).
 * What each value becomes for a model follows the Claude API thinking documentation, as the capability table
 * ({@code contexa.llm.model-capabilities.anthropic.thinking}) states it; Contexa picks none of these values itself.
 */
public enum AnthropicThinkingMode {

    /** Contexa sends no thinking field: the Spring AI default options, or else the model's own default, apply. */
    PROVIDER_DEFAULT,

    /** Thinking off, sent as the value the model takes for it; left out where the model cannot turn thinking off. */
    OFF,

    /** Adaptive thinking; Spring AI 1.1 cannot send it (its Anthropic options have no adaptive type). */
    ADAPTIVE,

    /** Thinking with a token budget (type enabled with budget_tokens), for the models that take it. */
    BUDGET;

    /** The mode a setting names, ignoring case; null for none or a name that is no mode. */
    public static AnthropicThinkingMode from(Object value) {
        if (value instanceof AnthropicThinkingMode mode) {
            return mode;
        }
        String text = value != null ? value.toString().trim().toUpperCase(Locale.ROOT) : "";
        for (AnthropicThinkingMode mode : values()) {
            if (mode.name().equals(text)) {
                return mode;
            }
        }
        return null;
    }
}
