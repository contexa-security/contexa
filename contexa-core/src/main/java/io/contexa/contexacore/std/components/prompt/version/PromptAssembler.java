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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Makes a version of a prompt (plan 3.5 and 3.8): the product document as it is, or a base version with an
 * organization's document applied. Before it applies a document it checks it: a fixed part changed or deleted, a part
 * or a place the base does not have, an added part without a title or a text, a key twice, and a finished prompt too
 * long for the model are refused, every one named. A version is made only from a document without a problem.
 */
public final class PromptAssembler {

    /** The groups of the system parts: the judgment text, the answer and the answer format. */
    static final Set<String> GROUPS = Set.of(AssembledPrompt.JUDGMENT, "output", "format");

    /**
     * The longest finished prompt allowed (plan 3.5 check 4): the model's context in tokens, the tokens of the answer
     * and of the longest recent user prompt.
     */
    public record LengthLimit(int contextTokens, int answerTokens, int longestUserPromptTokens) {
    }

    /**
     * What the check of a document found: its problems (none when it can be saved), and the estimated system prompt
     * tokens of the base and of the new version (shown, never refused for itself).
     */
    public record Check(List<PromptVersionProblem> problems, int baseSystemTokens, int systemTokens) {

        public Check {
            problems = List.copyOf(problems);
        }

        public boolean passed() {
            return problems.isEmpty();
        }
    }

    /** The product version: the product document's parts as they are, after the check of its form. */
    public AssembledPrompt product(PromptVersionDocument document) {
        List<PromptVersionProblem> problems = new ArrayList<>();
        if (document.kind() != PromptVersionDocument.Kind.PRODUCT) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, "kind", "a product document"));
        }
        if (document.release() == null || document.release().isBlank()) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.MISSING_FIELD, "release", null));
        }
        productParts(document.system(), "system", true, problems);
        productParts(document.user(), "user", false, problems);
        Map<String, String> corrections = new LinkedHashMap<>();
        for (PromptVersionDocument.Item item : document.corrections()) {
            if (corrections.put(item.key(), item.text()) != null) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.DUPLICATE_KEY,
                        "corrections." + item.key(), null));
            }
            if (blank(item.text())) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.EMPTY_TEXT,
                        "corrections." + item.key(), null));
            }
        }
        if (!problems.isEmpty()) {
            throw new PromptVersionDocumentException(problems);
        }
        return new AssembledPrompt(document.prompt(), document.release(), document.title(), document.system(),
                document.user(), corrections, false);
    }

    private static void productParts(List<PromptVersionDocument.Part> parts, String list, boolean system,
                                     List<PromptVersionProblem> problems) {
        Set<String> keys = new HashSet<>();
        for (PromptVersionDocument.Part part : parts) {
            String where = list + "." + part.key();
            if (!keys.add(part.key())) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.DUPLICATE_KEY, where, null));
            }
            if (system && part.group() != null && !GROUPS.contains(part.group())) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, where + ".group",
                        part.group()));
            }
            if (blank(part.text()) && part.items().isEmpty()) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.EMPTY_TEXT, where, null));
            }
            if (blank(part.title())) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.EMPTY_TITLE, where, null));
            }
        }
    }

    /** The version an organization's document makes on its base; refused with every problem when it has one. */
    public AssembledPrompt apply(AssembledPrompt base, PromptVersionDocument changes) {
        return apply(base, changes, null);
    }

    /** As {@link #apply(AssembledPrompt, PromptVersionDocument)}, refusing a prompt the limit does not hold. */
    public AssembledPrompt apply(AssembledPrompt base, PromptVersionDocument changes, LengthLimit limit) {
        Check check = check(base, changes, limit);
        if (!check.passed()) {
            throw new PromptVersionDocumentException(check.problems());
        }
        return applied(base, changes);
    }

    /** The check of an organization's document on its base (plan 3.5, the checks before saving, and 3.6). */
    public Check check(AssembledPrompt base, PromptVersionDocument changes, LengthLimit limit) {
        List<PromptVersionProblem> problems = new ArrayList<>();
        if (changes.kind() == PromptVersionDocument.Kind.RENDERED) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.RENDERED_DOCUMENT, "kind", null));
        }
        else if (changes.kind() != PromptVersionDocument.Kind.ORGANIZATION) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, "kind",
                    "an organization's document"));
        }
        if (!base.prompt().equals(changes.prompt())) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.OTHER_PROMPT, "prompt", changes.prompt()));
        }
        if (blank(changes.basedOn()) && blank(changes.basedOnHash())) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.NO_BASE, "basedOn", null));
        }
        checkParts(base.system(), changes.system(), "system", true, problems);
        checkParts(base.user(), changes.user(), "user", false, problems);
        if (!changes.corrections().isEmpty()) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.LOCKED_PART, "corrections", null));
        }
        int baseTokens = systemTokens(base);
        int tokens = baseTokens;
        if (problems.isEmpty()) {
            tokens = systemTokens(applied(base, changes));
            if (limit != null && tokens + limit.longestUserPromptTokens() + limit.answerTokens() > limit.contextTokens()) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.TOO_LONG, null,
                        tokens + " + " + limit.longestUserPromptTokens() + " + " + limit.answerTokens() + " > "
                                + limit.contextTokens()));
            }
        }
        return new Check(problems, baseTokens, tokens);
    }

    private static void checkParts(List<PromptVersionDocument.Part> base, List<PromptVersionDocument.Part> changes,
                                   String list, boolean system, List<PromptVersionProblem> problems) {
        Map<String, PromptVersionDocument.Part> byKey = new LinkedHashMap<>();
        base.forEach(part -> byKey.put(part.key(), part));
        Set<String> seen = new HashSet<>();
        Set<String> added = new HashSet<>();
        for (PromptVersionDocument.Part change : changes) {
            String where = list + "." + change.key();
            if (!seen.add(change.key())) {
                problems.add(new PromptVersionProblem(PromptVersionProblem.Code.DUPLICATE_KEY, where, null));
                continue;
            }
            PromptVersionDocument.Part current = byKey.get(change.key());
            switch (change.action()) {
                case ADD -> {
                    if (current != null) {
                        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.DUPLICATE_KEY, where, null));
                    }
                    PromptVersionDocument.Part place = byKey.get(change.addAfter());
                    boolean placeable = place != null && (!system || AssembledPrompt.JUDGMENT.equals(
                            place.group() != null ? place.group() : AssembledPrompt.JUDGMENT));
                    if (!placeable && !added.contains(change.addAfter())) {
                        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.UNKNOWN_PLACE, where,
                                change.addAfter()));
                    }
                    if (blank(change.title())) {
                        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.EMPTY_TITLE, where, null));
                    }
                    if (blank(change.text())) {
                        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.EMPTY_TEXT, where, null));
                    }
                    added.add(change.key());
                }
                case CHANGE -> {
                    if (current == null) {
                        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.UNKNOWN_PART, where, null));
                    }
                    else if (current.isLocked() || current.prepared()) {
                        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.LOCKED_PART, where, null));
                    }
                    if (blank(change.text())) {
                        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.EMPTY_TEXT, where, null));
                    }
                }
                case DELETE -> {
                    if (current == null) {
                        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.UNKNOWN_PART, where, null));
                    }
                    else if (current.isLocked() && current.action() != PromptVersionDocument.Action.INCLUDE) {
                        // A prepared part a version included may be taken out again; any other fixed part stays.
                        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.LOCKED_PART, where, null));
                    }
                }
                case INCLUDE -> {
                    if (current == null) {
                        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.UNKNOWN_PART, where, null));
                    }
                    else if (!current.prepared()) {
                        problems.add(new PromptVersionProblem(PromptVersionProblem.Code.NOT_PREPARED, where, null));
                    }
                }
                default -> problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BAD_VALUE, where,
                        change.action().name()));
            }
        }
    }

    /** The base with the changes applied; the changes passed their check. */
    private static AssembledPrompt applied(AssembledPrompt base, PromptVersionDocument changes) {
        List<PromptVersionDocument.Part> system = applied(base.system(), changes.system(), true);
        List<PromptVersionDocument.Part> user = applied(base.user(), changes.user(), false);
        boolean organization = base.organizationParts() || changes.system().stream().anyMatch(PromptAssembler::authored)
                || changes.user().stream().anyMatch(PromptAssembler::authored);
        String title = !blank(changes.title()) ? changes.title() : base.title();
        return new AssembledPrompt(base.prompt(), base.release(), title, system, user, base.corrections(),
                organization);
    }

    /** Whether the change puts an organization's own words in the prompt (a change or an addition). */
    private static boolean authored(PromptVersionDocument.Part change) {
        return change.action() == PromptVersionDocument.Action.CHANGE || change.action() == PromptVersionDocument.Action.ADD;
    }

    private static List<PromptVersionDocument.Part> applied(List<PromptVersionDocument.Part> base,
                                                            List<PromptVersionDocument.Part> changes, boolean system) {
        List<PromptVersionDocument.Part> parts = new ArrayList<>(base);
        Map<String, String> lastAddedAfter = new LinkedHashMap<>();
        for (PromptVersionDocument.Part change : changes) {
            int at = change.action() == PromptVersionDocument.Action.ADD ? -1 : indexOf(parts, change.key());
            switch (change.action()) {
                case CHANGE -> parts.set(at, parts.get(at).changed(change.title(), change.text()));
                case DELETE -> {
                    PromptVersionDocument.Part current = parts.get(at);
                    if (current.action() == PromptVersionDocument.Action.INCLUDE) {
                        parts.set(at, prepared(current));
                    }
                    else {
                        parts.remove(at);
                    }
                }
                case INCLUDE -> parts.set(at, parts.get(at).included());
                case ADD -> {
                    // Parts added after the same part follow each other in the document's order.
                    String after = lastAddedAfter.getOrDefault(change.addAfter(), change.addAfter());
                    int place = indexOf(parts, after) + 1;
                    // An added paragraph does not split a list: it follows the parts that continue the one it names.
                    while (place < parts.size() && parts.get(place).join() == PromptVersionDocument.Join.CONTINUE
                            && parts.get(place).action() != PromptVersionDocument.Action.ADD) {
                        place++;
                    }
                    PromptVersionDocument.Part added = new PromptVersionDocument.Part(change.key(), change.title(),
                            Boolean.FALSE, PromptVersionDocument.Join.PARAGRAPH, true,
                            system ? AssembledPrompt.JUDGMENT : null, null, false, change.text(), null, null, null,
                            PromptVersionDocument.Action.ADD, change.addAfter());
                    parts.add(place, added);
                    lastAddedAfter.put(change.addAfter(), change.key());
                }
                default -> {
                }
            }
        }
        return parts;
    }

    /** A prepared part taken out again by a later version. */
    private static PromptVersionDocument.Part prepared(PromptVersionDocument.Part part) {
        return new PromptVersionDocument.Part(part.key(), part.title(), part.locked(), part.join(), part.heading(),
                part.group(), part.when(), true, part.text(), part.whenText(), part.items(), part.effects(),
                PromptVersionDocument.Action.BASE, part.addAfter());
    }

    private static int indexOf(List<PromptVersionDocument.Part> parts, String key) {
        for (int index = 0; index < parts.size(); index++) {
            if (parts.get(index).key().equals(key)) {
                return index;
            }
        }
        throw new IllegalStateException("No part " + key + " after the check");
    }

    /**
     * The estimated system prompt tokens of a version (a quarter of the characters, as the heuristic estimator
     * counts): every part it draws under any condition, with its longest text.
     */
    public static int systemTokens(AssembledPrompt version) {
        long characters = 0;
        for (PromptVersionDocument.Part part : version.system()) {
            if (part.prepared()) {
                continue;
            }
            int longest = part.text() != null ? part.text().codePointCount(0, part.text().length()) : 0;
            for (String variant : part.whenText().values()) {
                longest = Math.max(longest, variant.codePointCount(0, variant.length()));
            }
            characters += longest + (part.heading() && part.title() != null ? part.title().length() + 2 : 0) + 1;
            for (PromptVersionDocument.Item item : part.items()) {
                characters += item.key().length() + (item.text() != null ? item.text().length() : 0) + 4;
            }
        }
        return (int) Math.ceil(characters / 4.0d);
    }

    private static boolean blank(String text) {
        return text == null || text.isBlank();
    }
}
