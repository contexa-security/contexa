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

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.BiFunction;

/**
 * One version of a prompt as the assembler made it (plan 3.8): the product parts with an organization's changes,
 * deletions, additions and inclusions applied, in their order. It is what the engine draws a prompt from; it holds no
 * value of a request. Two versions that draw the same prompt have the same content hash, worked out once when the
 * version is made: a request that keys a cache by it does no work for it.
 */
public final class AssembledPrompt {

    /** The condition of the parts drawn only in a version an organization changed (the precedence sentence). */
    public static final String ORGANIZATION_PARTS = "organization-parts";
    /** The group of a system part that has none: the judgment text. */
    public static final String JUDGMENT = "judgment";

    private final String prompt;
    private final String release;
    private final String title;
    private final List<PromptVersionDocument.Part> system;
    private final List<PromptVersionDocument.Part> user;
    private final Map<String, String> corrections;
    private final boolean organizationParts;
    private final String contentHash;

    /**
     * @param prompt            the prompt, such as {@code cortex.security-decision}
     * @param release           the Contexa release of the product document the version stands on
     * @param title             the version's title
     * @param system            the system parts in order; a prepared part not included is kept, marked prepared
     * @param user              the user blocks in order
     * @param corrections       the sentences that ask again, by key
     * @param organizationParts whether an organization changed or added a part (the precedence sentence is drawn)
     */
    public AssembledPrompt(String prompt, String release, String title, List<PromptVersionDocument.Part> system,
                           List<PromptVersionDocument.Part> user, Map<String, String> corrections,
                           boolean organizationParts) {
        this.prompt = Objects.requireNonNull(prompt, "prompt");
        this.release = release;
        this.title = title;
        this.system = List.copyOf(system);
        this.user = List.copyOf(user);
        this.corrections = Map.copyOf(corrections);
        this.organizationParts = organizationParts;
        this.contentHash = hashOf(this.prompt, this.organizationParts, this.system, this.user, this.corrections);
    }

    public String prompt() {
        return prompt;
    }

    public String release() {
        return release;
    }

    public String title() {
        return title;
    }

    public List<PromptVersionDocument.Part> system() {
        return system;
    }

    public List<PromptVersionDocument.Part> user() {
        return user;
    }

    public Map<String, String> corrections() {
        return corrections;
    }

    public boolean organizationParts() {
        return organizationParts;
    }

    /** Two versions are the same when they draw the same prompt: when their content hashes are the same. */
    @Override
    public boolean equals(Object other) {
        return other instanceof AssembledPrompt version && contentHash.equals(version.contentHash);
    }

    @Override
    public int hashCode() {
        return contentHash.hashCode();
    }

    @Override
    public String toString() {
        return "AssembledPrompt[" + prompt + ", " + release + ", " + title + ", " + contentHash + "]";
    }

    /** The system part of the key, prepared or not. */
    public Optional<PromptVersionDocument.Part> systemPart(String key) {
        return system.stream().filter(part -> part.key().equals(key)).findFirst();
    }

    /** The user block of the key. */
    public Optional<PromptVersionDocument.Part> userBlock(String key) {
        return user.stream().filter(part -> part.key().equals(key)).findFirst();
    }

    /** The parts of a system group the version draws under the conditions, in order. */
    public List<PromptVersionDocument.Part> drawnParts(String group, Set<String> conditions) {
        Set<String> holding = holding(conditions);
        return system.stream()
                .filter(part -> group.equals(part.group() != null ? part.group() : JUDGMENT))
                .filter(part -> !part.prepared())
                .filter(part -> part.when() == null || holding.contains(part.when()))
                .toList();
    }

    /**
     * The text of a system group under the conditions: each part after a blank line, or right after the one before
     * it when it continues it, its title as a heading line when it has one. A part the drawer gives a text for (a part
     * of items, one with values to fill in) is drawn with that text; the drawer returns null for the others.
     */
    public String draw(String group, Set<String> conditions,
                       BiFunction<PromptVersionDocument.Part, Set<String>, String> drawer) {
        return draw(drawnParts(group, conditions), holding(conditions), drawer);
    }

    /** The text of the parts, in their order, under the conditions that hold, as {@link #draw(String, Set, BiFunction)}. */
    public static String draw(List<PromptVersionDocument.Part> parts, Set<String> holding,
                              BiFunction<PromptVersionDocument.Part, Set<String>, String> drawer) {
        StringBuilder text = new StringBuilder();
        boolean first = true;
        for (PromptVersionDocument.Part part : parts) {
            String drawn = drawer != null ? drawer.apply(part, holding) : null;
            String body = drawn != null ? drawn : part.textUnder(holding);
            if (body == null || body.isEmpty()) {
                continue;
            }
            if (!first && part.join() == PromptVersionDocument.Join.PARAGRAPH) {
                text.append('\n');
            }
            if (part.heading() && part.title() != null) {
                text.append(part.title()).append(":\n");
            }
            text.append(body);
            if (!body.endsWith("\n")) {
                text.append('\n');
            }
            first = false;
        }
        return text.toString();
    }

    /** The correction sentence of the key with the values in place of their {name}; null when the version has none. */
    public String correction(String key, Map<String, String> values) {
        String text = corrections.get(key);
        return text != null ? fill(text, values) : null;
    }

    /** The meaning of each item of a system part, by key, in order; empty when the version has no such part. */
    public Map<String, String> itemTexts(String partKey) {
        Map<String, String> texts = new LinkedHashMap<>();
        systemPart(partKey).ifPresent(part -> part.items().forEach(item -> texts.put(item.key(), item.text())));
        return texts;
    }

    /** What the included prepared parts ask the engine to do besides drawing them. */
    public Set<String> effects() {
        Set<String> effects = new LinkedHashSet<>();
        system.stream().filter(part -> !part.prepared()).forEach(part -> effects.addAll(part.effects()));
        return effects;
    }

    /**
     * The content hash (plan 3.7): the sha-256 of the parts in their order with everything that decides what is drawn,
     * so two versions that draw the same prompt have the same hash.
     */
    public String contentHash() {
        return contentHash;
    }

    private static String hashOf(String prompt, boolean organizationParts, List<PromptVersionDocument.Part> system,
                                 List<PromptVersionDocument.Part> user, Map<String, String> corrections) {
        StringBuilder canonical = new StringBuilder("prompt=").append(prompt).append('\n');
        canonical.append("organizationParts=").append(organizationParts).append('\n');
        system.forEach(part -> canonical(canonical, "system", part));
        user.forEach(part -> canonical(canonical, "user", part));
        new TreeMap<>(corrections).forEach((key, text) ->
                canonical.append("correction|").append(key).append('|').append(text).append('\n'));
        return PromptBundleHashes.sha256Hex(canonical.toString());
    }

    private static void canonical(StringBuilder canonical, String list, PromptVersionDocument.Part part) {
        canonical.append(list).append('|').append(part.key()).append('|').append(part.title()).append('|')
                .append(part.isLocked()).append('|').append(part.join()).append('|').append(part.heading()).append('|')
                .append(part.group()).append('|').append(part.when()).append('|').append(part.prepared()).append('|')
                .append(part.text()).append('|').append(new TreeMap<>(part.whenText())).append('|')
                .append(part.effects()).append('\n');
        part.items().forEach(item -> canonical.append("  item|").append(item.key()).append('|').append(item.text())
                .append('|').append(item.use()).append('\n'));
    }

    /** The conditions that hold for the version: the given ones, and the organization parts when it has any. */
    public Set<String> holding(Set<String> conditions) {
        Set<String> holding = new LinkedHashSet<>(conditions != null ? conditions : Set.of());
        if (organizationParts) {
            holding.add(ORGANIZATION_PARTS);
        }
        return holding;
    }

    /** The text with each {name} of the values replaced by its value. */
    public static String fill(String text, Map<String, String> values) {
        String filled = text;
        if (values != null) {
            for (Map.Entry<String, String> value : values.entrySet()) {
                filled = filled.replace("{" + value.getKey() + "}", value.getValue() != null ? value.getValue() : "");
            }
        }
        return filled;
    }
}
