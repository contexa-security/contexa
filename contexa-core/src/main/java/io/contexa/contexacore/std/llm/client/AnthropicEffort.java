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
 * The effort levels of Anthropic's {@code output_config.effort}, lowest first (Claude API effort documentation). A layer
 * sets one with {@code contexa.security.tiered.layerN.anthropic-effort}; Spring AI 1.1 cannot send any of them.
 */
public enum AnthropicEffort {

    LOW,
    MEDIUM,
    HIGH,
    XHIGH,
    MAX;

    /** The value the Claude API takes. */
    public String wireValue() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** The level a setting names, ignoring case; null for none or a name that is no level. */
    public static AnthropicEffort from(Object value) {
        if (value instanceof AnthropicEffort effort) {
            return effort;
        }
        String text = value != null ? value.toString().trim().toUpperCase(Locale.ROOT) : "";
        for (AnthropicEffort effort : values()) {
            if (effort.name().equals(text)) {
                return effort;
            }
        }
        return null;
    }
}
