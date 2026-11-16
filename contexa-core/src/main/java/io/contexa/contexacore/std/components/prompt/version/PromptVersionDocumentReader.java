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

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.error.YAMLException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Reads a prompt version document (plan 3.6) and checks its form: the fields of the form and nothing else, the value
 * kinds, and the fields an organization's part cannot set. It reads with the safe constructor of SnakeYAML, so a
 * document builds no object but maps, lists and plain values, and duplicate keys are refused. Whether the changes fit
 * their base is the assembler's check ({@link PromptAssembler#check}).
 */
public final class PromptVersionDocumentReader {

    /** The largest document read, in characters: far more than a full prompt, far less than a heap. */
    static final int MAX_DOCUMENT_CODE_POINTS = 1_000_000;

    private static final Set<String> DOCUMENT_FIELDS = Set.of("prompt", "kind", "release", "basedOn", "basedOnHash",
            "title", "description", "system", "user", "corrections");
    private static final Set<String> PRODUCT_PART_FIELDS = Set.of("key", "title", "locked", "join", "heading", "group",
            "when", "prepared", "text", "whenText", "items", "effects");
    private static final Set<String> ORGANIZATION_PART_FIELDS = Set.of("key", "title", "text", "add-after", "delete",
            "include");
    private static final Set<String> ITEM_FIELDS = Set.of("key", "text", "use");

    public PromptVersionDocument read(String yaml) {
        List<PromptVersionProblem> problems = new ArrayList<>();
        PromptVersionDocument document = read(yaml, problems);
        if (!problems.isEmpty()) {
            throw new PromptVersionDocumentException(problems);
        }
        return document;
    }

    private PromptVersionDocument read(String yaml, List<PromptVersionProblem> problems) {
        Object loaded;
        try {
            loaded = yaml(yaml);
        }
        catch (YAMLException exception) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.FORMAT, null, firstLine(exception.getMessage())));
            return null;
        }
        if (!(loaded instanceof Map<?, ?> map)) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.FORMAT, null, "not a mapping"));
            return null;
        }
        unknownFields(map, DOCUMENT_FIELDS, null, problems);
        String prompt = text(map, "prompt", null, problems, true);
        String release = text(map, "release", null, problems, false);
        String basedOn = text(map, "basedOn", null, problems, false);
        PromptVersionDocument.Kind kind = kind(map, release, problems);
        boolean product = kind == PromptVersionDocument.Kind.PRODUCT || kind == PromptVersionDocument.Kind.RENDERED;
        List<PromptVersionDocument.Part> system = parts(map.get("system"), "system", product, problems);
        List<PromptVersionDocument.Part> user = parts(map.get("user"), "user", product, problems);
        List<PromptVersionDocument.Item> corrections = items(map.get("corrections"), "corrections", problems);
        if (prompt == null || kind == null) {
            return null;
        }
        return new PromptVersionDocument(prompt, kind, release, basedOn,
                text(map, "basedOnHash", null, problems, false), text(map, "title", null, problems, false),
                text(map, "description", null, problems, false), system, user, corrections);
    }

    private static Object yaml(String yaml) {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setMaxAliasesForCollections(0);
        options.setCodePointLimit(MAX_DOCUMENT_CODE_POINTS);
        return new Yaml(new SafeConstructor(options)).load(yaml != null ? yaml : "");
    }

    private static PromptVersionDocument.Kind kind(Map<?, ?> map, String release,
                                                   List<PromptVersionProblem> problems) {
        Object value = map.get("kind");
        if (value == null) {
            return release != null ? PromptVersionDocument.Kind.PRODUCT : PromptVersionDocument.Kind.ORGANIZATION;
        }
        try {
            return PromptVersionDocument.Kind.valueOf(String.valueOf(value).trim().toUpperCase(Locale.ROOT));
        }
        catch (IllegalArgumentException exception) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, "kind", String.valueOf(value)));
            return null;
        }
    }

    private List<PromptVersionDocument.Part> parts(Object value, String list, boolean product,
                                                   List<PromptVersionProblem> problems) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> entries)) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, list, "not a list"));
            return List.of();
        }
        List<PromptVersionDocument.Part> parts = new ArrayList<>();
        for (int index = 0; index < entries.size(); index++) {
            String where = list + "[" + index + "]";
            if (!(entries.get(index) instanceof Map<?, ?> entry)) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, where, "not a mapping"));
                continue;
            }
            String key = text(entry, "key", where, problems, true);
            if (key != null) {
                where = list + "." + key;
            }
            unknownFields(entry, product ? PRODUCT_PART_FIELDS : ORGANIZATION_PART_FIELDS, where, problems);
            PromptVersionDocument.Part part = product ? productPart(entry, key, where, problems)
                    : organizationPart(entry, key, where, problems);
            if (part != null) {
                parts.add(part);
            }
        }
        return parts;
    }

    private PromptVersionDocument.Part productPart(Map<?, ?> entry, String key, String where,
                                                   List<PromptVersionProblem> problems) {
        Boolean locked = flag(entry, "locked", where, problems);
        Boolean heading = flag(entry, "heading", where, problems);
        Boolean prepared = flag(entry, "prepared", where, problems);
        PromptVersionDocument.Join join = join(entry, where, problems);
        Map<String, String> whenText = textMap(entry.get("whenText"), where + ".whenText", problems);
        List<String> effects = texts(entry.get("effects"), where + ".effects", problems);
        List<PromptVersionDocument.Item> items = items(entry.get("items"), where + ".items", problems);
        if (key == null) {
            return null;
        }
        return new PromptVersionDocument.Part(key, text(entry, "title", where, problems, false),
                locked != null ? locked : Boolean.FALSE, join, Boolean.TRUE.equals(heading),
                text(entry, "group", where, problems, false), text(entry, "when", where, problems, false),
                Boolean.TRUE.equals(prepared), text(entry, "text", where, problems, false), whenText, items, effects,
                PromptVersionDocument.Action.BASE, null);
    }

    private PromptVersionDocument.Part organizationPart(Map<?, ?> entry, String key, String where,
                                                        List<PromptVersionProblem> problems) {
        Boolean delete = flag(entry, "delete", where, problems);
        Boolean include = flag(entry, "include", where, problems);
        String addAfter = text(entry, "add-after", where, problems, false);
        String title = text(entry, "title", where, problems, false);
        String text = text(entry, "text", where, problems, false);
        int actions = (Boolean.TRUE.equals(delete) ? 1 : 0) + (Boolean.TRUE.equals(include) ? 1 : 0)
                + (addAfter != null ? 1 : 0);
        if (actions > 1) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, where,
                    "one of add-after, delete and include"));
        }
        if ((Boolean.TRUE.equals(delete) || Boolean.TRUE.equals(include)) && (title != null || text != null)) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.UNKNOWN_FIELD, where,
                    "a deleted or included part has no title or text"));
        }
        if (key == null) {
            return null;
        }
        PromptVersionDocument.Action action = Boolean.TRUE.equals(delete) ? PromptVersionDocument.Action.DELETE
                : Boolean.TRUE.equals(include) ? PromptVersionDocument.Action.INCLUDE
                : addAfter != null ? PromptVersionDocument.Action.ADD : PromptVersionDocument.Action.CHANGE;
        return new PromptVersionDocument.Part(key, title, null, null,
                action == PromptVersionDocument.Action.ADD, null, null, false, text, null, null, null, action,
                addAfter);
    }

    private List<PromptVersionDocument.Item> items(Object value, String where, List<PromptVersionProblem> problems) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> entries)) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, where, "not a list"));
            return List.of();
        }
        List<PromptVersionDocument.Item> items = new ArrayList<>();
        for (int index = 0; index < entries.size(); index++) {
            String at = where + "[" + index + "]";
            if (!(entries.get(index) instanceof Map<?, ?> entry)) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, at, "not a mapping"));
                continue;
            }
            unknownFields(entry, ITEM_FIELDS, at, problems);
            String key = text(entry, "key", at, problems, true);
            if (key != null) {
                items.add(new PromptVersionDocument.Item(key, text(entry, "text", at, problems, false),
                        text(entry, "use", at, problems, false)));
            }
        }
        return items;
    }

    private static void unknownFields(Map<?, ?> map, Set<String> fields, String where,
                                      List<PromptVersionProblem> problems) {
        for (Object field : map.keySet()) {
            if (!fields.contains(String.valueOf(field))) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.UNKNOWN_FIELD,
                        where != null ? where + "." + field : String.valueOf(field), null));
            }
        }
    }

    private static String text(Map<?, ?> map, String field, String where, List<PromptVersionProblem> problems,
                               boolean required) {
        Object value = map.get(field);
        String at = where != null ? where + "." + field : field;
        if (value == null) {
            if (required) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.MISSING_FIELD, at, null));
            }
            return null;
        }
        if (value instanceof Map<?, ?> || value instanceof List<?>) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, at, "not a text"));
            return null;
        }
        return String.valueOf(value);
    }

    private static Boolean flag(Map<?, ?> map, String field, String where, List<PromptVersionProblem> problems) {
        Object value = map.get(field);
        if (value == null || value instanceof Boolean) {
            return (Boolean) value;
        }
        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, where + "." + field,
                "true or false"));
        return null;
    }

    private static PromptVersionDocument.Join join(Map<?, ?> map, String where, List<PromptVersionProblem> problems) {
        Object value = map.get("join");
        if (value == null) {
            return null;
        }
        try {
            return PromptVersionDocument.Join.valueOf(String.valueOf(value).trim().toUpperCase(Locale.ROOT));
        }
        catch (IllegalArgumentException exception) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, where + ".join",
                    String.valueOf(value)));
            return null;
        }
    }

    private static Map<String, String> textMap(Object value, String where, List<PromptVersionProblem> problems) {
        if (value == null) {
            return Map.of();
        }
        if (!(value instanceof Map<?, ?> map)) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, where, "not a mapping"));
            return Map.of();
        }
        Map<String, String> texts = new LinkedHashMap<>();
        map.forEach((key, text) -> texts.put(String.valueOf(key), String.valueOf(text)));
        return texts;
    }

    private static List<String> texts(Object value, String where, List<PromptVersionProblem> problems) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> list)) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, where, "not a list"));
            return List.of();
        }
        return list.stream().map(String::valueOf).toList();
    }

    private static String firstLine(String message) {
        if (message == null) {
            return null;
        }
        int end = message.indexOf('\n');
        return end >= 0 ? message.substring(0, end) : message;
    }
}
