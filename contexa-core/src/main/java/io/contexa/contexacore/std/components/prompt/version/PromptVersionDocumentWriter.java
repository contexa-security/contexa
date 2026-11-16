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

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Writes a version as a document (plan 3.6): an organization's changes, which can be read back and imported, or a
 * rendered copy of a whole version, for reading only ({@code kind: rendered}). A text of several lines is written as a
 * literal block when the block gives it back exactly, else as a quoted text; what the reader reads back is what was
 * written.
 */
public final class PromptVersionDocumentWriter {

    /** The changes of an organization's document. */
    public String write(PromptVersionDocument document) {
        StringBuilder yaml = new StringBuilder();
        field(yaml, "", "prompt", document.prompt());
        field(yaml, "", "kind", document.kind().name().toLowerCase(Locale.ROOT));
        field(yaml, "", "release", document.release());
        field(yaml, "", "basedOn", document.basedOn());
        field(yaml, "", "basedOnHash", document.basedOnHash());
        field(yaml, "", "title", document.title());
        field(yaml, "", "description", document.description());
        boolean product = document.kind() != PromptVersionDocument.Kind.ORGANIZATION;
        parts(yaml, "system", document.system(), product);
        parts(yaml, "user", document.user(), product);
        if (!document.corrections().isEmpty()) {
            yaml.append("corrections:\n");
            items(yaml, "  ", document.corrections());
        }
        return yaml.toString();
    }

    /** A rendered copy of the whole version: every part with all it holds, marked so that it cannot be imported. */
    public String writeRendered(AssembledPrompt version, String title) {
        List<PromptVersionDocument.Item> corrections = new TreeMap<>(version.corrections()).entrySet().stream()
                .map(entry -> new PromptVersionDocument.Item(entry.getKey(), entry.getValue(), null)).toList();
        return write(new PromptVersionDocument(version.prompt(), PromptVersionDocument.Kind.RENDERED,
                version.release(), null, version.contentHash(), title != null ? title : version.title(), null,
                version.system(), version.user(), corrections));
    }

    private static void parts(StringBuilder yaml, String list, List<PromptVersionDocument.Part> parts, boolean product) {
        if (parts.isEmpty()) {
            return;
        }
        yaml.append(list).append(":\n");
        for (PromptVersionDocument.Part part : parts) {
            yaml.append("  - key: ").append(scalar(part.key(), "    ")).append('\n');
            String indent = "    ";
            if (product) {
                field(yaml, indent, "title", part.title());
                yaml.append(indent).append("locked: ").append(part.isLocked()).append('\n');
                if (part.join() != PromptVersionDocument.Join.PARAGRAPH) {
                    yaml.append(indent).append("join: ").append(part.join().name().toLowerCase(Locale.ROOT))
                            .append('\n');
                }
                if (part.heading()) {
                    yaml.append(indent).append("heading: true\n");
                }
                field(yaml, indent, "group", part.group());
                field(yaml, indent, "when", part.when());
                if (part.prepared()) {
                    yaml.append(indent).append("prepared: true\n");
                }
                if (!part.effects().isEmpty()) {
                    yaml.append(indent).append("effects: [").append(String.join(", ", part.effects())).append("]\n");
                }
                if (!part.items().isEmpty()) {
                    yaml.append(indent).append("items:\n");
                    items(yaml, indent + "  ", part.items());
                }
                field(yaml, indent, "text", part.text());
                if (!part.whenText().isEmpty()) {
                    yaml.append(indent).append("whenText:\n");
                    for (Map.Entry<String, String> variant : new TreeMap<>(part.whenText()).entrySet()) {
                        field(yaml, indent + "  ", variant.getKey(), variant.getValue());
                    }
                }
                continue;
            }
            switch (part.action()) {
                case DELETE -> yaml.append(indent).append("delete: true\n");
                case INCLUDE -> yaml.append(indent).append("include: true\n");
                case ADD -> {
                    field(yaml, indent, "add-after", part.addAfter());
                    field(yaml, indent, "title", part.title());
                    field(yaml, indent, "text", part.text());
                }
                default -> {
                    field(yaml, indent, "title", part.title());
                    field(yaml, indent, "text", part.text());
                }
            }
        }
    }

    private static void items(StringBuilder yaml, String indent, List<PromptVersionDocument.Item> items) {
        for (PromptVersionDocument.Item item : items) {
            yaml.append(indent).append("- key: ").append(scalar(item.key(), indent + "  ")).append('\n');
            field(yaml, indent + "  ", "text", item.text());
            field(yaml, indent + "  ", "use", item.use());
        }
    }

    private static void field(StringBuilder yaml, String indent, String name, String value) {
        if (value == null) {
            return;
        }
        yaml.append(indent).append(name).append(": ").append(scalar(value, indent + "  ")).append('\n');
    }

    /** The value as a literal block when the block gives it back exactly, else as a quoted text. */
    static String scalar(String value, String indent) {
        if (literal(value)) {
            boolean newline = value.endsWith("\n");
            String body = newline ? value.substring(0, value.length() - 1) : value;
            StringBuilder block = new StringBuilder(newline ? "|" : "|-");
            for (String line : body.split("\n", -1)) {
                block.append('\n').append(line.isEmpty() ? "" : indent + line);
            }
            return block.toString();
        }
        return quoted(value);
    }

    /**
     * Whether a literal block gives the value back exactly: several lines, no tab or carriage return, a first line
     * that is not empty and does not start with a space, no trailing empty line, and no line ending in a space.
     */
    private static boolean literal(String value) {
        if (!value.contains("\n") || value.contains("\t") || value.contains("\r") || value.startsWith(" ")
                || value.startsWith("\n") || value.endsWith("\n\n")) {
            return false;
        }
        for (String line : value.split("\n", -1)) {
            if (line.endsWith(" ")) {
                return false;
            }
        }
        return true;
    }

    private static String quoted(String value) {
        StringBuilder quoted = new StringBuilder("\"");
        for (char character : value.toCharArray()) {
            switch (character) {
                case '\\' -> quoted.append("\\\\");
                case '"' -> quoted.append("\\\"");
                case '\n' -> quoted.append("\\n");
                case '\r' -> quoted.append("\\r");
                case '\t' -> quoted.append("\\t");
                default -> {
                    if (character < 0x20) {
                        quoted.append(String.format(Locale.ROOT, "\\x%02x", (int) character));
                    }
                    else {
                        quoted.append(character);
                    }
                }
            }
        }
        return quoted.append('"').toString();
    }
}
