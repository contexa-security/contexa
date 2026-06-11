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
package io.contexa.contexacore.std.pipeline.step;

import java.util.Locale;

public enum StructuredOutputPolicy {
    ALLOW_RAW_FALLBACK,
    RAW_FORBIDDEN;

    public boolean allowsRawFallback() {
        return this == ALLOW_RAW_FALLBACK;
    }

    public static StructuredOutputPolicy fromValue(Object value, StructuredOutputPolicy fallback) {
        if (value == null) {
            return fallback;
        }
        String normalized = value.toString().trim().toUpperCase(Locale.ROOT);
        for (StructuredOutputPolicy policy : values()) {
            if (policy.name().equals(normalized)) {
                return policy;
            }
        }
        return fallback;
    }
}
