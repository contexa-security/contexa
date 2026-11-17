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
package io.contexa.contexacore.std.components.prompt.version;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The text a version of a prompt other than the security decision draws (plan 3.8, 3.11): the parts of a system group
 * or the user parts in their order, each under the conditions that hold and with the values of the call in place of
 * their {@code {name}}. A value is put in once: a value that holds a {@code {name}} of its own (a requester's text)
 * stays as it is.
 */
public final class PromptDrawing {

    private static final Pattern NAME = Pattern.compile("\\{([A-Za-z0-9-]+)}");

    private PromptDrawing() {
    }

    /** The text of the version's system parts of the group, under the conditions, with the values put in. */
    public static String system(AssembledPrompt version, String group, Set<String> conditions, Map<String, String> values) {
        return version.draw(group, conditions, (part, holding) -> fill(part.textUnder(holding), values));
    }

    /** The text of the version's user parts in their order, under the conditions, with the values put in. */
    public static String user(AssembledPrompt version, Set<String> conditions, Map<String, String> values) {
        Set<String> holding = new HashSet<>(conditions);
        if (version.organizationParts()) {
            holding.add(AssembledPrompt.ORGANIZATION_PARTS);
        }
        List<PromptVersionDocument.Part> parts = version.user().stream()
                .filter(part -> !part.prepared())
                .filter(part -> part.when() == null || holding.contains(part.when()))
                .toList();
        return AssembledPrompt.draw(parts, holding, (part, under) -> fill(part.textUnder(under), values));
    }

    /** The text of an item of a part, the system's or the user's, with the values put in; null when the version has none. */
    public static String item(AssembledPrompt version, String partKey, String itemKey, Map<String, String> values) {
        PromptVersionDocument.Part part = version.systemPart(partKey).or(() -> version.userBlock(partKey)).orElse(null);
        if (part == null) {
            return null;
        }
        return part.items().stream().filter(item -> item.key().equals(itemKey)).findFirst()
                .map(item -> fill(item.text(), values)).orElse(null);
    }

    /** The text with the values in place of their {@code {name}}, each put in once; a name with no value stays. */
    public static String fill(String text, Map<String, String> values) {
        if (text == null || values == null || values.isEmpty()) {
            return text;
        }
        Matcher matcher = NAME.matcher(text);
        StringBuilder filled = new StringBuilder();
        while (matcher.find()) {
            String name = matcher.group(1);
            String value = values.containsKey(name) ? values.get(name) : matcher.group();
            matcher.appendReplacement(filled, Matcher.quoteReplacement(value != null ? value : ""));
        }
        matcher.appendTail(filled);
        return filled.toString();
    }
}
