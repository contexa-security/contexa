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

import java.util.List;
import java.util.Optional;

/**
 * The OSS default slot plan provider: a line of a v20 block whose label is a dictionary entry gets a plan that carries
 * the entry; any other line (the v19 sections) gets the unscoped plan, as before.
 */
public class PromptDictionarySlotPlanProvider implements PromptSlotPlanProvider {

    private static final String SOURCE_PRODUCER = "PromptDictionary";

    private final List<PromptDictionaryEntry> entries;
    private final String cacheScopeKey;

    public PromptDictionarySlotPlanProvider(List<PromptDictionaryEntry> entries, String dictionaryVersion) {
        this.entries = entries == null ? List.of() : List.copyOf(entries);
        this.cacheScopeKey = "PROMPT_DICTIONARY:" + dictionaryVersion;
    }

    @Override
    public PromptSlotPlan planFor(String sectionKey, String labelKey) {
        return entryFor(sectionKey, labelKey)
                .map(entry -> plan(entry, labelKey))
                .orElseGet(() -> PromptSlotPlan.unscoped(sectionKey, labelKey));
    }

    /**
     * The plan of a dictionary slot key ({@code DECISION FACTS.PolicySatisfied}), whose label is the entry name; nothing
     * for any other key (W3-14: a runtime governance rule names its slot by the key).
     */
    @Override
    public List<PromptSlotPlan> plansForSlotKey(String promptKey, String slotKey) {
        if (slotKey == null) {
            return List.of();
        }
        return entries.stream()
                .filter(entry -> slotKey.equals(slotKey(entry)))
                .map(entry -> plan(entry, entry.name()))
                .toList();
    }

    @Override
    public String cacheScopeKey() {
        return cacheScopeKey;
    }

    /** The dictionary entry of a line, when the section is a v20 block and the label one of its entries. */
    public Optional<PromptDictionaryEntry> entryFor(String sectionKey, String labelKey) {
        Optional<PromptBlock> block = PromptBlock.fromSectionKey(sectionKey);
        if (block.isEmpty() || labelKey == null) {
            return Optional.empty();
        }
        String label = labelKey.trim();
        return entries.stream()
                .filter(entry -> entry.block() == block.get() && entry.matchesLabel(label))
                .findFirst();
    }

    public List<PromptDictionaryEntry> entries() {
        return entries;
    }

    private static String slotKey(PromptDictionaryEntry entry) {
        return entry.block().title() + "." + entry.name();
    }

    private static PromptSlotPlan plan(PromptDictionaryEntry entry, String labelKey) {
        return new PromptSlotPlan(
                slotKey(entry),
                entry.block().title(),
                labelKey,
                entry.sourcePath(),
                SOURCE_PRODUCER,
                entry.priority(),
                entry.truncationAllowed() ? "STANDARD" : "FORBID_TRUNCATION",
                entry);
    }
}
