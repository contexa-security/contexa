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
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryRenderer;
import io.contexa.contexacore.autonomous.context.prompt.PromptMissingNotation;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDictionary;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Whether a sealed v20 user prompt keeps the dictionary's rules as the renderer draws them: line feeds only and a final
 * line feed; known block headers in dictionary order, each once; only entry lines of their block, each once and in
 * dictionary order; values in the entry's form or its missing text; numbered lines counted from 1 up to the entry's
 * cap and one {@code +n more} line; and fact ids with the block's prefix in drawn order, on every decision fact a
 * reason code may cite. Each line counts once; a line that breaks several rules is pointed at for the first.
 */
public final class DictionaryContractCheck implements PromptInspectionCheck {

    public static final String CODE = "DICTIONARY_CONTRACT";


    private final List<PromptDictionaryEntry> entries;

    public DictionaryContractCheck() {
        this.entries = SecurityDecisionPromptDictionary.ENTRIES;
    }

    @Override
    public String code() {
        return CODE;
    }

    @Override
    public boolean dictionaryPromptOnly() {
        return true;
    }

    @Override
    public void inspect(PromptInspectionTally tally) {
        InspectedPrompt prompt = tally.subject().prompt();
        if (prompt.lineFeedsOnly()) {
            tally.matched();
        }
        else {
            tally.mismatch(tally.mismatchFinding().expected("\\n").actual("\\r\\n")
                    .reason("the prompt must use line feeds only").build());
        }
        if (prompt.endsWithLineFeed()) {
            tally.matched();
        }
        else {
            tally.mismatch(tally.mismatchFinding().reason("the prompt must end with a final line feed").build());
        }
        new Reader(tally).read(prompt.lines());
    }

    /** Reads the lines in order, keeping what the rules need of the lines before. */
    private final class Reader {

        private final PromptInspectionTally tally;
        private final Set<PromptBlock> seenBlocks = EnumSet.noneOf(PromptBlock.class);
        private final Map<PromptBlock, Integer> factIds = new EnumMap<>(PromptBlock.class);
        private PromptBlock block;
        private boolean skipping;
        private int lastBlockOrdinal = -1;
        private int lastEntryIndex = -1;
        private Set<String> labels = new HashSet<>();
        private Map<PromptDictionaryEntry, Integer> numbers = new HashMap<>();

        private Reader(PromptInspectionTally tally) {
            this.tally = tally;
        }

        private void read(List<InspectedPrompt.Line> lines) {
            for (InspectedPrompt.Line line : lines) {
                switch (line.kind()) {
                    case BLANK -> {
                    }
                    case HEADER -> header(line);
                    case OTHER -> {
                        if (!skipping) {
                            tally.mismatch(finding(line).actual(line.text())
                                    .reason("the line is not a dictionary line (Label: value)").build());
                        }
                    }
                    case ENTRY -> entry(line);
                }
            }
        }

        private void header(InspectedPrompt.Line line) {
            labels = new HashSet<>();
            numbers = new HashMap<>();
            lastEntryIndex = -1;
            PromptBlock named = line.block();
            if (named == null) {
                skipping = true;
                block = null;
                tally.mismatch(finding(line).actual(line.text()).reason("the header names no block of the dictionary").build());
                return;
            }
            if (!seenBlocks.add(named)) {
                skipping = true;
                block = null;
                tally.mismatch(finding(line).actual(line.text()).reason("the block is drawn twice").build());
                return;
            }
            skipping = false;
            block = named;
            if (named.ordinal() < lastBlockOrdinal) {
                tally.mismatch(finding(line).actual(line.text())
                        .expected(PromptBlock.values()[lastBlockOrdinal].title() + " before " + named.title() + " is out of order")
                        .reason("the block is out of the dictionary's block order").build());
                return;
            }
            lastBlockOrdinal = named.ordinal();
            tally.matched(line);
        }

        private void entry(InspectedPrompt.Line line) {
            if (skipping) {
                return;
            }
            String label = line.entryLine().label();
            String value = line.entryLine().value();
            if (block == null) {
                tally.mismatch(finding(line).entry(label).actual(line.text()).reason("the line stands outside a block").build());
                return;
            }
            PromptDictionaryEntry entry = entryOf(label);
            if (entry == null) {
                tally.mismatch(finding(line).entry(label).actual(line.text()).reason("the line is not an entry of the block").build());
                return;
            }
            if (!labels.add(label)) {
                tally.mismatch(finding(line).entry(label).actual(line.text()).reason("the entry is drawn twice").build());
                keepFactIdOrder(line, entry);
                return;
            }
            int index = entries.indexOf(entry);
            if (index < lastEntryIndex) {
                tally.mismatch(finding(line).entry(label).actual(line.text())
                        .expected("after " + entries.get(lastEntryIndex).name())
                        .reason("the entry is out of dictionary order").build());
                keepFactIdOrder(line, entry);
                return;
            }
            lastEntryIndex = index;
            boolean overflow = false;
            if (entry.indexed()) {
                int number = Integer.parseInt(label.substring(entry.stem().length()));
                int expected = numbers.getOrDefault(entry, 0) + 1;
                numbers.put(entry, number);
                if (number != expected) {
                    tally.mismatch(finding(line).entry(label).expected(entry.stem() + expected).actual(label)
                            .reason("the numbered lines must count from 1 without gaps").build());
                    keepFactIdOrder(line, entry);
                    return;
                }
                overflow = entry.listCap() != null && number == entry.listCap() + 1;
                if (entry.listCap() != null && number > entry.listCap() + 1) {
                    tally.mismatch(finding(line).entry(label).expected("at most " + entry.listCap() + " lines and one +n more")
                            .actual(label).reason("the numbered lines go beyond the entry's cap").build());
                    keepFactIdOrder(line, entry);
                    return;
                }
            }
            if (!valueKeepsForm(entry, value, overflow)) {
                tally.mismatch(finding(line).entry(label)
                        .expected(overflow ? PromptDictionaryRenderer.OVERFLOW.pattern() : entry.formatPattern()).actual(value)
                        .reason("the value is out of the entry form").build());
                keepFactIdOrder(line, entry);
                return;
            }
            if (!factIdKept(line, entry, label)) {
                return;
            }
            tally.matched(line);
        }

        /**
         * A line a reason code may cite carries the ID of its block in the drawn order, in every block with an ID prefix
         * (dictionary 1.5, P3 extra 12); a line counting the records over a list's cap carries none.
         */
        private boolean factIdKept(InspectedPrompt.Line line, PromptDictionaryEntry entry, String label) {
            String factId = line.factId();
            String prefix = block.factPrefix();
            boolean citable = PromptDictionaryRenderer.citesFactId(block, entry, line.entryLine().value());
            if (factId == null) {
                if (!citable) {
                    return true;
                }
                String expected = prefix + nextFactNumber();
                tally.mismatch(finding(line).entry(label).expected(expected)
                        .reason("the cited line carries no fact id").build());
                return false;
            }
            if (!citable) {
                tally.mismatch(finding(line).entry(label).factId(factId)
                        .expected(prefix == null ? "no fact id" : "a fact id only on a required " + block.title() + " line")
                        .actual(factId).reason("the line carries a fact id it may not carry").build());
                return false;
            }
            // A cited line takes its place in the block's order whatever ID it carries, so one wrong ID is one finding.
            String expected = prefix + nextFactNumber();
            if (!factId.startsWith(prefix)) {
                tally.mismatch(finding(line).entry(label).factId(factId).expected(expected).actual(factId)
                        .reason("the line carries the fact id of another block").build());
                return false;
            }
            if (!expected.equals(factId)) {
                tally.mismatch(finding(line).entry(label).factId(factId).expected(expected).actual(factId)
                        .reason("the fact ids must follow the drawn order").build());
                return false;
            }
            return true;
        }

        /**
         * A cited line another check pointed at still takes its place in its block's ID order, by the ID it carries
         * when that is of the block, else by the next number, so that one wrong line is one finding.
         */
        private void keepFactIdOrder(InspectedPrompt.Line line, PromptDictionaryEntry entry) {
            String prefix = block.factPrefix();
            if (!PromptDictionaryRenderer.citesFactId(block, entry, line.entryLine().value())) {
                return;
            }
            String factId = line.factId();
            if (factId != null && factId.startsWith(prefix) && factId.length() > prefix.length()
                    && factId.substring(prefix.length()).chars().allMatch(Character::isDigit)) {
                factIds.put(block, Integer.parseInt(factId.substring(prefix.length())));
                return;
            }
            nextFactNumber();
        }

        private int nextFactNumber() {
            int next = factIds.getOrDefault(block, 0) + 1;
            factIds.put(block, next);
            return next;
        }

        private PromptDictionaryEntry entryOf(String label) {
            for (PromptDictionaryEntry entry : entries) {
                if (entry.block() == block && entry.matchesLabel(label)) {
                    return entry;
                }
            }
            return null;
        }

        private PromptInspectionFinding.Builder finding(InspectedPrompt.Line line) {
            return tally.mismatchFinding()
                    .block(block != null ? block.title() : line.block() != null ? line.block().title() : null)
                    .lineNumber(line.number())
                    .factId(line.factId());
        }
    }

    private static boolean valueKeepsForm(PromptDictionaryEntry entry, String value, boolean overflow) {
        if (overflow) {
            return PromptDictionaryRenderer.OVERFLOW.matcher(value).matches();
        }
        if (entry.acceptsValue(value)) {
            return true;
        }
        return entry.missing() == PromptMissingNotation.RENDERED_VALUE && value.equals(entry.missingText());
    }
}
