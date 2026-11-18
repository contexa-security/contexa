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
package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptDrawing;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * What the IAM prompt templates draw alike from a version (plan 3.11): the system prompt of a JSON answer (the
 * judgment parts, then the output and format parts inside the output tags, then the host's metadata) and the list of
 * items a policy may use, its labels from the version.
 */
final class VersionedTemplateDrawing {

    static final String OUTPUT = "output";
    static final String FORMAT = "format";

    private VersionedTemplateDrawing() {
    }

    /** The system prompt of a JSON answer the version draws under the conditions. */
    static String jsonSystem(AssembledPrompt version, Set<String> conditions, Map<String, String> values,
                             String systemMetadata) {
        StringBuilder prompt = new StringBuilder();
        prompt.append(PromptDrawing.system(version, AssembledPrompt.JUDGMENT, conditions, values).trim());
        prompt.append("\n\n<output_format>\n");
        prompt.append(PromptDrawing.system(version, OUTPUT, conditions, values));
        prompt.append(PromptDrawing.system(version, FORMAT, conditions, values));
        prompt.append("\n</output_format>");
        if (systemMetadata != null && !systemMetadata.isBlank()) {
            prompt.append("\n\n<context>\n").append(systemMetadata).append("\n</context>");
        }
        return prompt.toString();
    }

    /** The text of an item of the version's part; the empty text when the version has none. */
    static String item(AssembledPrompt version, String part, String item) {
        String text = PromptDrawing.item(version, part, item, Map.of());
        return text != null ? text : "";
    }

    /** The roles, permissions and conditions a policy may use, with the labels of the version's part. */
    static String availableItems(AssembledPrompt version, String part, PolicyGenerationItem.AvailableItems items) {
        if (items == null) {
            return item(version, part, "none");
        }
        StringBuilder info = new StringBuilder();
        if (items.roles() != null && !items.roles().isEmpty()) {
            info.append(item(version, part, "role-list")).append('\n');
            items.roles().forEach(role ->
                    info.append(String.format(Locale.ROOT, "- %s (ID: %d)\n", role.name(), role.id())));
        }
        if (items.permissions() != null && !items.permissions().isEmpty()) {
            info.append('\n').append(item(version, part, "permission-list")).append('\n');
            items.permissions().forEach(permission -> {
                info.append(String.format(Locale.ROOT, "- %s (ID: %d)", permission.name(), permission.id()));
                if (permission.targetType() != null && permission.resourceIdentifier() != null) {
                    info.append(' ').append(PromptDrawing.item(version, part, "protects", Map.of(
                            "type", permission.targetType(),
                            "method", permission.httpMethod() != null ? permission.httpMethod() : "",
                            "target", permission.resourceIdentifier())));
                }
                info.append('\n');
            });
        }
        if (items.conditions() != null && !items.conditions().isEmpty()) {
            info.append('\n').append(item(version, part, "condition-list")).append('\n');
            items.conditions().forEach(condition ->
                    info.append(String.format(Locale.ROOT, "- ID: %d, Name: %s\n", condition.id(), condition.name())));
        }
        return !info.isEmpty() ? info.toString() : item(version, part, "empty");
    }

    /** The text without its last line break, for a prompt that ends on its last sentence. */
    static String withoutLastBreak(String text) {
        return text.endsWith("\n") ? text.substring(0, text.length() - 1) : text;
    }
}
