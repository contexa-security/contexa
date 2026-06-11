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

import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class StructuredOutputCapabilityRegistry {

    private static final StructuredOutputCapabilityRegistry DEFAULT = new StructuredOutputCapabilityRegistry();

    private static final Map<String, String> MODEL_PREFIX_PROVIDER_FAMILIES = Map.of(
            "gpt-", "openai",
            "o1", "openai",
            "o3", "openai",
            "claude", "anthropic",
            "gemini", "google"
    );

    private static final List<String> NATIVE_STRUCTURED_PROVIDER_FAMILIES = List.of(
            "openai",
            "anthropic",
            "google"
    );

    private StructuredOutputCapabilityRegistry() {
    }

    public static StructuredOutputCapabilityRegistry defaultRegistry() {
        return DEFAULT;
    }

    public StructuredOutputCapability resolve(String modelHint, String providerHint, boolean targetTypePresent) {
        String normalizedProvider = normalize(providerHint);
        if (normalizedProvider != null) {
            String providerFamily = resolveProviderFamilyFromProviderHint(normalizedProvider);
            if (providerFamily != null) {
                return new StructuredOutputCapability(
                        providerFamily,
                        NATIVE_STRUCTURED_PROVIDER_FAMILIES.contains(providerFamily),
                        targetTypePresent,
                        "providerHint");
            }
        }

        String normalizedModel = normalize(modelHint);
        if (normalizedModel != null) {
            for (Map.Entry<String, String> entry : MODEL_PREFIX_PROVIDER_FAMILIES.entrySet()) {
                if (normalizedModel.startsWith(entry.getKey())) {
                    String providerFamily = entry.getValue();
                    return new StructuredOutputCapability(
                            providerFamily,
                            NATIVE_STRUCTURED_PROVIDER_FAMILIES.contains(providerFamily),
                            targetTypePresent,
                            "modelHint");
                }
            }
            if (normalizedModel.contains("gpt-4o") || normalizedModel.contains("gpt-5")) {
                return new StructuredOutputCapability("openai", true, targetTypePresent, "modelHint");
            }
            if (normalizedModel.contains("claude-")) {
                return new StructuredOutputCapability("anthropic", true, targetTypePresent, "modelHint");
            }
            if (normalizedModel.contains("gemini-")) {
                return new StructuredOutputCapability("google", true, targetTypePresent, "modelHint");
            }
        }

        return new StructuredOutputCapability(
                "unknown",
                false,
                targetTypePresent,
                "default");
    }

    private String resolveProviderFamilyFromProviderHint(String providerHint) {
        if (providerHint.contains("openai")) {
            return "openai";
        }
        if (providerHint.contains("anthropic") || providerHint.contains("claude")) {
            return "anthropic";
        }
        if (providerHint.contains("google") || providerHint.contains("gemini") || providerHint.contains("vertex")) {
            return "google";
        }
        if (providerHint.contains("ollama")) {
            return "ollama";
        }
        if (providerHint.contains("azure")) {
            return "azure-openai";
        }
        return null;
    }

    private String normalize(String text) {
        if (text == null) {
            return null;
        }
        String normalized = text.trim().toLowerCase(Locale.ROOT);
        return normalized.isEmpty() ? null : normalized;
    }
}
