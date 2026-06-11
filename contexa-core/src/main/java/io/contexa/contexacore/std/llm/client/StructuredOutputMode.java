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

public enum StructuredOutputMode {
    NATIVE_STRUCTURED,
    VALIDATED_CONVERTER,
    RAW_FORBIDDEN,
    LEGACY_RAW;

    public static StructuredOutputMode fromValue(Object value, StructuredOutputMode fallback) {
        if (value == null) {
            return fallback;
        }
        if (value instanceof StructuredOutputMode mode) {
            return mode;
        }
        String text = String.valueOf(value).trim();
        if (text.isEmpty()) {
            return fallback;
        }
        try {
            return StructuredOutputMode.valueOf(text.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return fallback;
        }
    }
}
