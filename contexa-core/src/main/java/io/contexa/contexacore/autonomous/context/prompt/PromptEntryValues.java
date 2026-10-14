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
package io.contexa.contexacore.autonomous.context.prompt;

import org.springframework.util.StringUtils;

import java.time.ZoneId;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The values of one prompt by dictionary entry: a value for a single line, the items of a numbered entry, the entries
 * the prompt does not know this time, block header qualifiers, and the entries whose values are on the event clock with
 * that clock's time zone. Names outside the dictionary are refused, so every drawn line is a dictionary entry. A value
 * given for an entry wins over marking it unknown.
 */
public final class PromptEntryValues {

    private final Map<PromptDictionaryEntry, String> values;
    private final Map<PromptDictionaryEntry, List<PromptListItem>> lines;
    private final Map<PromptDictionaryEntry, Unknown> unknown;
    private final Map<PromptBlock, String> headerQualifiers;
    private final ZoneId timeZone;
    private final Set<PromptDictionaryEntry> clocked;

    /**
     * Why an entry is not known this time (dictionary 1.4).
     *
     * @param kind   not integrated, or unavailable now
     * @param reason why it is unavailable now, null when there is nothing to add
     */
    record Unknown(PromptUnknownKind kind, String reason) {
    }

    private PromptEntryValues(Map<PromptDictionaryEntry, String> values, Map<PromptDictionaryEntry, List<PromptListItem>> lines,
                              Map<PromptDictionaryEntry, Unknown> unknown, Map<PromptBlock, String> headerQualifiers,
                              ZoneId timeZone, Set<PromptDictionaryEntry> clocked) {
        this.values = values;
        this.lines = lines;
        this.unknown = unknown;
        this.headerQualifiers = headerQualifiers;
        this.timeZone = timeZone;
        this.clocked = clocked;
    }

    public static Builder builder(List<PromptDictionaryEntry> entries) {
        return new Builder(entries);
    }

    String value(PromptDictionaryEntry entry) {
        return values.get(entry);
    }

    List<PromptListItem> lines(PromptDictionaryEntry entry) {
        return lines.getOrDefault(entry, List.of());
    }

    boolean unknown(PromptDictionaryEntry entry) {
        return unknown.containsKey(entry);
    }

    /** Why the entry is not known this time, or null when the caller did not mark it unknown. */
    Unknown unknownOf(PromptDictionaryEntry entry) {
        return unknown.get(entry);
    }

    String headerQualifier(PromptBlock block) {
        return headerQualifiers.get(block);
    }

    /** The time zone of the event clock the values are on, or null when the caller did not say. */
    ZoneId timeZone() {
        return timeZone;
    }

    /** Whether the entry's value is on the event clock (a time, an hour or a day of the week). */
    boolean clocked(PromptDictionaryEntry entry) {
        return clocked.contains(entry);
    }

    public static final class Builder {

        private final List<PromptDictionaryEntry> entries;
        private final Map<PromptDictionaryEntry, String> values = new LinkedHashMap<>();
        private final Map<PromptDictionaryEntry, List<PromptListItem>> lines = new LinkedHashMap<>();
        private final Map<PromptDictionaryEntry, Unknown> unknown = new LinkedHashMap<>();
        private final Map<PromptBlock, String> headerQualifiers = new EnumMap<>(PromptBlock.class);
        private final Set<PromptDictionaryEntry> clocked = new LinkedHashSet<>();
        private ZoneId timeZone;

        private Builder(List<PromptDictionaryEntry> entries) {
            this.entries = entries == null ? List.of() : List.copyOf(entries);
        }

        /** The value of a single-line entry; a blank value leaves the entry without a value. */
        public Builder value(PromptBlock block, String name, String value) {
            PromptDictionaryEntry entry = entry(block, name);
            if (entry.indexed()) {
                throw new IllegalArgumentException("Numbered entry " + name + " takes lines, not a value");
            }
            if (StringUtils.hasText(value)) {
                values.put(entry, value.trim());
            }
            return this;
        }

        /** The items of a numbered entry; the renderer orders them by the entry's list order. */
        public Builder lines(PromptBlock block, String name, List<PromptListItem> items) {
            PromptDictionaryEntry entry = entry(block, name);
            if (!entry.indexed()) {
                throw new IllegalArgumentException("Entry " + name + " is not numbered");
            }
            List<PromptListItem> kept = new ArrayList<>();
            if (items != null) {
                for (PromptListItem item : items) {
                    if (item != null && StringUtils.hasText(item.text())) {
                        kept.add(item);
                    }
                }
            }
            lines.put(entry, List.copyOf(kept));
            return this;
        }

        /**
         * An entry the prompt does not know this time because nothing gives it (not integrated); it goes to the UNKNOWN
         * block. A kind given before for the entry stays.
         */
        public Builder unknown(PromptBlock block, String name) {
            unknown.putIfAbsent(entry(block, name), new Unknown(PromptUnknownKind.NOT_INTEGRATED, null));
            return this;
        }

        /** An entry the prompt does not know this time, of that kind and for that reason; it goes to the UNKNOWN block. */
        public Builder unknown(PromptBlock block, String name, PromptUnknownKind kind, String reason) {
            unknown.put(entry(block, name), new Unknown(kind == null ? PromptUnknownKind.NOT_INTEGRATED : kind,
                    PromptUnknownKind.reasonText(reason)));
            return this;
        }

        public Builder headerQualifier(PromptBlock block, String qualifier) {
            if (block != null && StringUtils.hasText(qualifier)) {
                headerQualifiers.put(block, qualifier.trim());
            }
            return this;
        }

        /** The time zone of the event clock the values are on (W3-13). */
        public Builder timeZone(ZoneId zone) {
            this.timeZone = zone;
            return this;
        }

        /** The entry's value is on the event clock: a time, an hour or a day of the week (W3-13). */
        public Builder clocked(PromptBlock block, String name) {
            clocked.add(entry(block, name));
            return this;
        }

        public PromptEntryValues build() {
            return new PromptEntryValues(Map.copyOf(values), Map.copyOf(lines), Map.copyOf(unknown),
                    Map.copyOf(headerQualifiers), timeZone, Set.copyOf(clocked));
        }

        private PromptDictionaryEntry entry(PromptBlock block, String name) {
            for (PromptDictionaryEntry entry : entries) {
                if (entry.block() == block && entry.name().equals(name)) {
                    return entry;
                }
            }
            throw new IllegalArgumentException("No dictionary entry " + name + " in block "
                    + (block == null ? "null" : block.title()));
        }
    }
}
