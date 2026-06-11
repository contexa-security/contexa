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

public record PromptGovernanceResolutionContext(
        String registryScope,
        String promptKey,
        String templateKey,
        String tenantId,
        String resourceId,
        String resourceUrl,
        String httpMethod,
        Map<String, Object> attributes) {

    public PromptGovernanceResolutionContext {
        if (attributes == null || attributes.isEmpty()) {
            attributes = Map.of();
        }
        else {
            Map<String, Object> sanitized = new LinkedHashMap<>();
            attributes.forEach((key, value) -> {
                if (key != null && value != null) {
                    sanitized.put(key, value);
                }
            });
            attributes = Map.copyOf(sanitized);
        }
    }
}
