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
package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public record PromptGovernanceDescriptorResolution(
        PromptGovernanceDescriptor descriptor,
        Map<String, Object> supplementalMetadata) {

    public PromptGovernanceDescriptorResolution {
        descriptor = Objects.requireNonNull(descriptor, "descriptor");
        if (supplementalMetadata == null || supplementalMetadata.isEmpty()) {
            supplementalMetadata = Map.of();
        }
        else {
            Map<String, Object> sanitized = new LinkedHashMap<>();
            supplementalMetadata.forEach((key, value) -> {
                if (key != null && value != null) {
                    sanitized.put(key, value);
                }
            });
            supplementalMetadata = Map.copyOf(sanitized);
        }
    }

    public static PromptGovernanceDescriptorResolution fallback(
            PromptGovernanceDescriptor descriptor,
            PromptGovernanceResolutionContext context) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("registryScope", registryScope(context));
        metadata.put("governanceResolutionSource", "STATIC_PROMPT_DESCRIPTOR");
        metadata.put("promptGovernanceCacheState", "FALLBACK");
        return new PromptGovernanceDescriptorResolution(descriptor, metadata);
    }

    private static String registryScope(PromptGovernanceResolutionContext context) {
        if (context != null && context.registryScope() != null && !context.registryScope().isBlank()) {
            return context.registryScope().trim();
        }
        return "PLATFORM_GLOBAL";
    }
}
