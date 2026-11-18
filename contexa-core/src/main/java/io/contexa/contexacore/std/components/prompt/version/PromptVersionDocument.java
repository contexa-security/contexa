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
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * One prompt version document (plan 3.6): the product document of a Contexa release, which holds every part of the
 * prompt, or an organization's document, which names its base version and holds only what it changes, deletes or adds.
 * A document is one version; the sentences of the prompt live here and nowhere in the code.
 *
 * @param prompt      the prompt the document is for, such as {@code cortex.security-decision}
 * @param kind        a product document, an organization's changes, or a rendered copy (for reading only)
 * @param release     the Contexa release of a product document; null otherwise
 * @param basedOn     the number of the base version of an organization's document; null for a product document
 * @param basedOnHash the content hash of that base, written by a download so another server finds the same base
 * @param title       what the version is called
 * @param description what the version is for; may be null
 * @param system      the system parts, in their order for a product document
 * @param user        the user blocks, in their order for a product document
 * @param corrections the sentences that ask again for an answer that broke the output contract or a rule
 */
public record PromptVersionDocument(
        String prompt,
        Kind kind,
        String release,
        String basedOn,
        String basedOnHash,
        String title,
        String description,
        List<Part> system,
        List<Part> user,
        List<Item> corrections) {

    public PromptVersionDocument {
        Objects.requireNonNull(prompt, "prompt");
        Objects.requireNonNull(kind, "kind");
        system = system == null ? List.of() : List.copyOf(system);
        user = user == null ? List.of() : List.copyOf(user);
        corrections = corrections == null ? List.of() : List.copyOf(corrections);
    }

    /** What a document is. */
    public enum Kind {
        /** The full prompt of a Contexa release. */
        PRODUCT,
        /** An organization's changes to a base version. */
        ORGANIZATION,
        /** A full copy of an assembled version, written for reading; it cannot be imported. */
        RENDERED
    }

    /** How a part follows the one before it. */
    public enum Join {
        /** After a blank line. */
        PARAGRAPH,
        /** Right after the part before it, continuing its list. */
        CONTINUE
    }

    /** What a part of an organization's document does to its base. */
    public enum Action {
        /** A part of the product document. */
        BASE,
        /** Replaces the text (and the title when given) of a part of the base. */
        CHANGE,
        /** Takes a part of the base out. */
        DELETE,
        /**
         * A new part, placed after the part {@link Part#addAfter()} names; in an assembled version, a part an
         * organization added, whether a later version changed it or not.
         */
        ADD,
        /** Puts a prepared part of the product document in. */
        INCLUDE
    }

    /**
     * One part of the system prompt or one block of the user prompt.
     *
     * @param key       the part's name, unique in its list
     * @param title     what the part is called; drawn as its heading when {@code heading} says so
     * @param locked    a part an organization cannot change or delete (Contexa's rules); null in an organization's part
     * @param join      how the part follows the one before it
     * @param heading   whether the title is drawn as a heading line ({@code Title:}) before the text
     * @param group     the section of the system prompt the part belongs to: judgment, output or format
     * @param when      the condition under which the part is drawn (a conditional fixed part); null when always
     * @param prepared  a part the product prepares and leaves out until a version includes it
     * @param text      the part's text; null for a part made of items
     * @param whenText  the text the part is drawn with under a condition, by condition
     * @param items     the named lines of the part: the reason codes, a block's lines, a rule's lines
     * @param effects   what the engine does besides drawing a prepared part once a version includes it
     * @param action    what an organization's part does to the base ({@link Action#BASE} in a product document)
     * @param addAfter  the part an added part follows
     */
    public record Part(
            String key,
            String title,
            Boolean locked,
            Join join,
            boolean heading,
            String group,
            String when,
            boolean prepared,
            String text,
            Map<String, String> whenText,
            List<Item> items,
            List<String> effects,
            Action action,
            String addAfter) {

        public Part {
            Objects.requireNonNull(key, "key");
            join = join == null ? Join.PARAGRAPH : join;
            whenText = whenText == null ? Map.of() : Map.copyOf(whenText);
            items = items == null ? List.of() : List.copyOf(items);
            effects = effects == null ? List.of() : List.copyOf(effects);
            action = action == null ? Action.BASE : action;
        }

        /** Whether an organization cannot change or delete the part. */
        public boolean isLocked() {
            return Boolean.TRUE.equals(locked);
        }

        /** The text the part is drawn with under the conditions that hold: its text for the first that names one. */
        public String textUnder(Set<String> conditions) {
            for (Map.Entry<String, String> variant : new TreeMap<>(whenText).entrySet()) {
                if (conditions.contains(variant.getKey())) {
                    return variant.getValue();
                }
            }
            return text;
        }

        /**
         * The same part with another text and title, as a change of an organization makes it. A part an organization
         * added stays an added part (K131): a later version that changes it, and every version after, draws and counts
         * it as the organization's own, at the place it was added.
         */
        Part changed(String newTitle, String newText) {
            return new Part(key, newTitle != null ? newTitle : title, locked, join, heading, group, when, prepared,
                    newText, Map.of(), items, effects, action == Action.ADD ? Action.ADD : Action.CHANGE, addAfter);
        }

        /** The same part, put in by a version (a prepared part included). */
        Part included() {
            return new Part(key, title, locked, join, heading, group, when, false, text, whenText, items, effects,
                    Action.INCLUDE, addAfter);
        }
    }

    /**
     * One named line of a part.
     *
     * @param key  the line's name: a reason code, a block's line label, a rule
     * @param text the line's text or meaning
     * @param use  what the decision uses the line for (a block's line); null otherwise
     */
    public record Item(String key, String text, String use) {

        public Item {
            Objects.requireNonNull(key, "key");
        }
    }
}
