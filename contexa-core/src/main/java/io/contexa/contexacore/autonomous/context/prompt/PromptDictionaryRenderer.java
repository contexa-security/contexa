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

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Draws the user blocks of a dictionary prompt (v20): the blocks in dictionary order, each under its header, one line
 * per entry in dictionary order, the dictionary's missing notation for entries without a value, numbered lines up to
 * the entry's cap followed by the count of the rest, and line feeds only.
 *
 * <p>An entry without a value is drawn by its missing notation: the dictionary's text, no line, or its name in the
 * UNKNOWN block. An entry that must always be present but has no value, and an entry the caller marks unknown, go to
 * the UNKNOWN block as well; nothing is made up. A numbered entry without items draws no line (its state entry says
 * why).</p>
 *
 * <p>The UNKNOWN line names each kind once (dictionary 1.4): not-integrated (nothing gives the fact, the default) and
 * unavailable-now (its source could not give it for this request, with the reason). A fact block whose drawn entries
 * share one source grade names it once in its header (dictionary 1.1, 1.2).</p>
 */
public final class PromptDictionaryRenderer {

    private static final String UNKNOWN_ENTRY = "Unknown";
    /** The line counting the items over a list's cap ({@code +3 more}), with the count (R1b-3: shared with the inspector). */
    public static final Pattern OVERFLOW = Pattern.compile("\\+(\\d+) more");

    private final List<PromptDictionaryEntry> entries;
    private final PromptSlotPlanProvider plans;
    private final PromptDictionarySlotPlanProvider dictionaryPlans;
    private final PromptSlotRenderer lineRenderer = new PromptSlotRenderer();

    public PromptDictionaryRenderer(List<PromptDictionaryEntry> entries, PromptSlotPlanProvider plans) {
        this.entries = List.copyOf(entries);
        this.dictionaryPlans = new PromptDictionarySlotPlanProvider(this.entries, "renderer");
        this.plans = plans == null ? dictionaryPlans : plans;
    }

    public PromptEntryValues.Builder values() {
        return PromptEntryValues.builder(entries);
    }

    public PromptDictionaryRendering render(PromptEntryValues values) {
        return render(values, Set.of());
    }

    /**
     * Draws the values without the withheld entries (W3-7: entries a prompt over its budget takes out). A withheld
     * entry is not drawn at all, not even with its missing notation, and is not named as unknown.
     */
    public PromptDictionaryRendering render(PromptEntryValues values, Set<PromptDictionaryEntry> withheld) {
        Map<PromptUnknownKind, TreeMap<String, String>> unknowns = new EnumMap<>(PromptUnknownKind.class);
        Map<PromptDictionaryEntry, List<String[]>> drawn = new LinkedHashMap<>();
        PromptDictionaryEntry unknownEntry = null;
        for (PromptDictionaryEntry entry : entries) {
            if (withheld.contains(entry)) {
                continue;
            }
            if (entry.block() == PromptBlock.UNKNOWN && UNKNOWN_ENTRY.equals(entry.name())) {
                unknownEntry = entry;
                continue;
            }
            drawn.put(entry, linesOf(entry, values, unknowns));
        }
        TreeSet<String> unknownNames = new TreeSet<>(PromptListOrder::compareCodePoints);
        unknowns.values().forEach(named -> unknownNames.addAll(named.keySet()));
        if (unknownEntry != null) {
            String given = values.value(unknownEntry);
            List<String[]> lines = new ArrayList<>();
            if (StringUtils.hasText(given)) {
                lines.add(new String[] {unknownEntry.name(), given});
            }
            else if (!unknownNames.isEmpty()) {
                lines.add(new String[] {unknownEntry.name(), unknownLine(unknowns)});
            }
            drawn.put(unknownEntry, lines);
        }

        StringBuilder text = new StringBuilder();
        List<PromptSlot> slots = new ArrayList<>();
        List<PromptBlock> blocks = new ArrayList<>();
        Map<String, String> factIds = new LinkedHashMap<>();
        for (PromptBlock block : PromptBlock.values()) {
            int cited = 0;
            StringBuilder body = new StringBuilder();
            List<PromptSlot> blockSlots = new ArrayList<>();
            Set<PromptSourceGrade> grades = EnumSet.noneOf(PromptSourceGrade.class);
            boolean clocked = false;
            for (PromptDictionaryEntry entry : entries) {
                if (entry.block() != block) {
                    continue;
                }
                for (String[] line : drawn.getOrDefault(entry, List.of())) {
                    PromptSlot slot = slotFor(entry, line[0], line[1]);
                    String rendered = lineRenderer.renderLine(slot);
                    // Dictionary 1.5 (W3-13, P3 extra 12): a line a reason code may cite carries the ID of its block, in
                    // the block's drawn order; a line counting the records over a list's cap is no record to cite.
                    if (!rendered.isEmpty() && citesFactId(block, entry, line[1])) {
                        String id = block.factPrefix() + (++cited);
                        factIds.put(line[0], id);
                        rendered = factIdText(id) + rendered;
                    }
                    body.append(rendered);
                    blockSlots.add(slot);
                    grades.addAll(entry.grades());
                    clocked |= values.clocked(entry);
                }
            }
            if (blockSlots.isEmpty()) {
                continue;
            }
            if (!blocks.isEmpty()) {
                text.append('\n');
            }
            String grade = block != PromptBlock.UNKNOWN && grades.size() == 1 ? grades.iterator().next().word() : null;
            // Dictionary 1.1: a block that drew a value on the event clock names the clock's time zone once (W3-13).
            String zone = clocked && values.timeZone() != null ? "time zone " + values.timeZone().getId() : null;
            text.append(header(block, grade, values.headerQualifier(block), zone)).append(body);
            slots.addAll(blockSlots);
            blocks.add(block);
        }
        return new PromptDictionaryRendering(text.toString(), List.copyOf(slots), List.copyOf(blocks),
                List.copyOf(unknownNames), Collections.unmodifiableMap(factIds));
    }

    private List<String[]> linesOf(PromptDictionaryEntry entry, PromptEntryValues values,
                                   Map<PromptUnknownKind, TreeMap<String, String>> unknowns) {
        List<String[]> lines = new ArrayList<>();
        if (entry.indexed()) {
            String stem = entry.stem();
            List<PromptListItem> items = entry.listOrder().sort(values.lines(entry));
            if (items.isEmpty()) {
                if (values.unknown(entry)) {
                    addUnknown(unknowns, stem, values.unknownOf(entry));
                }
                return lines;
            }
            int shown = shownItems(entry, items.size());
            for (int index = 0; index < shown; index++) {
                lines.add(new String[] {stem + (index + 1), items.get(index).text()});
            }
            if (shown < items.size()) {
                lines.add(new String[] {stem + (shown + 1), overflowValue(items.size() - shown)});
            }
            return lines;
        }
        String value = values.value(entry);
        if (StringUtils.hasText(value)) {
            lines.add(new String[] {entry.name(), value});
            return lines;
        }
        if (values.unknown(entry)) {
            addUnknown(unknowns, entry.name(), values.unknownOf(entry));
            return lines;
        }
        switch (entry.missing()) {
            case RENDERED_VALUE -> lines.add(new String[] {entry.name(), entry.missingText()});
            case UNKNOWN_BLOCK, ALWAYS_PRESENT -> addUnknown(unknowns, entry.name(), null);
            case LINE_OMITTED, BLOCK_OMITTED -> {
            }
        }
        return lines;
    }

    private PromptSlot slotFor(PromptDictionaryEntry entry, String label, String value) {
        PromptSlotPlan plan = plans.planFor(entry.block().title(), label);
        if (plan == null || plan.dictionaryEntry() == null) {
            plan = dictionaryPlans.planFor(entry.block().title(), label);
        }
        return plan.bind(value, value, null);
    }

    /** A name of the UNKNOWN line under its kind; without a kind the host has no integration for the fact. */
    private static void addUnknown(Map<PromptUnknownKind, TreeMap<String, String>> unknowns, String name,
                                   PromptEntryValues.Unknown unknown) {
        PromptUnknownKind kind = unknown != null ? unknown.kind() : PromptUnknownKind.NOT_INTEGRATED;
        unknowns.computeIfAbsent(kind, ignored -> new TreeMap<>(PromptListOrder::compareCodePoints))
                .put(name, unknown != null ? unknown.reason() : null);
    }

    /** {@code not-integrated: A, B; unavailable-now: C (reason)}: the kinds in their order, names by code point. */
    private static String unknownLine(Map<PromptUnknownKind, TreeMap<String, String>> unknowns) {
        List<String> parts = new ArrayList<>();
        for (PromptUnknownKind kind : PromptUnknownKind.values()) {
            TreeMap<String, String> named = unknowns.get(kind);
            if (named == null || named.isEmpty()) {
                continue;
            }
            List<String> names = new ArrayList<>();
            named.forEach((name, reason) -> names.add(name + (StringUtils.hasText(reason) ? " (" + reason + ")" : "")));
            parts.add(kind.word() + ": " + String.join(", ", names));
        }
        return String.join("; ", parts);
    }

    private static String header(PromptBlock block, String grade, String qualifier, String zone) {
        List<String> parts = new ArrayList<>();
        if (StringUtils.hasText(grade)) {
            parts.add(grade);
        }
        if (StringUtils.hasText(qualifier)) {
            parts.add(qualifier.trim());
        }
        if (StringUtils.hasText(zone)) {
            parts.add(zone);
        }
        return block.header(parts);
    }

    /** How many items of a list the entry shows: all of them, or as many as its cap (R1b-3: shared). */
    public static int shownItems(PromptDictionaryEntry entry, int items) {
        return entry.listCap() == null ? items : Math.min(entry.listCap(), items);
    }

    /** {@code +3 more}: the line after a list's cap counting the items it does not show (R1b-3: shared). */
    public static String overflowValue(int hidden) {
        return "+" + hidden + " more";
    }

    /**
     * Whether a line of the entry with this value carries its block's fact id (dictionary 1.5, W3-13, P3 extra 12): a
     * required line of a block with an id prefix, except the line counting a list's items over its cap (R1b-3: shared
     * with the inspector).
     */
    public static boolean citesFactId(PromptBlock block, PromptDictionaryEntry entry, String value) {
        return block.factPrefix() != null && PromptDictionaryEntry.PRIORITY_REQUIRED.equals(entry.priority())
                && !(entry.indexed() && value != null && OVERFLOW.matcher(value).matches());
    }

    /** {@code [F3] }: a fact id as it stands in front of its line (R1b-3: shared). */
    public static String factIdText(String id) {
        return "[" + id + "] ";
    }
}
