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
package io.contexa.contexacore.std.pipeline;

import java.util.Locale;

public enum PipelineFailurePolicy {
    SYNTHETIC_FALLBACK_RESPONSE,
    PROPAGATE_ERROR;

    public boolean propagatesError() {
        return this == PROPAGATE_ERROR;
    }

    public static PipelineFailurePolicy fromValue(Object value, PipelineFailurePolicy fallback) {
        if (value == null) {
            return fallback;
        }
        if (value instanceof PipelineFailurePolicy policy) {
            return policy;
        }
        String normalized = String.valueOf(value).trim().toUpperCase(Locale.ROOT);
        for (PipelineFailurePolicy policy : values()) {
            if (policy.name().equals(normalized)) {
                return policy;
            }
        }
        return fallback;
    }
}
