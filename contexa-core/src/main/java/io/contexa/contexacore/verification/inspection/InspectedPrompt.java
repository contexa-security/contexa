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
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryLine;

import java.util.ArrayList;
import java.util.List;

/**
 * A sealed user prompt read line by line as a v20 dictionary prompt: block headers, entry lines with their fact id,
 * blank lines and any other line, each with its 1-based line number and the block it stands in. Reading never
 * corrects the text; a carriage return or a missing final line feed is noted for the contract check.
 */
public record InspectedPrompt(List<Line> lines, boolean lineFeedsOnly, boolean endsWithLineFeed) {

    public InspectedPrompt {
        lines = lines == null ? List.of() : List.copyOf(lines);
    }

    /** What a line of the prompt is. */
    public enum Kind {
        /** A block header ({@code === TITLE ===} or {@code === TITLE (qualifier) ===}). */
        HEADER,
        /** A {@code Label: value} line, with or without a fact id. */
        ENTRY,
        /** An empty line. */
        BLANK,
        /** Any other line. */
        OTHER
    }

    /**
     * One line of the prompt.
     *
     * @param number          1-based line number
     * @param text            the line without its line break
     * @param kind            what the line is
     * @param block           the block of a header, or the block an entry line stands in; null when none is known
     * @param headerQualifier the text in parentheses of a header, or null
     * @param entryLine       the label and value of an entry line, or null
     */
    public record Line(int number, String text, Kind kind, PromptBlock block, String headerQualifier,
                       PromptDictionaryLine entryLine) {

        /** The fact id of an entry line without its brackets ({@code F3}), or null. */
        public String factId() {
            if (entryLine == null || entryLine.factId().isEmpty()) {
                return null;
            }
            String head = entryLine.factId().trim();
            return head.substring(1, head.length() - 1);
        }
    }

    public static InspectedPrompt parse(String text) {
        if (text == null || text.isEmpty()) {
            return new InspectedPrompt(List.of(), true, true);
        }
        boolean lineFeedsOnly = text.indexOf('\r') < 0;
        boolean endsWithLineFeed = text.endsWith("\n");
        String body = endsWithLineFeed ? text.substring(0, text.length() - 1) : text;
        String[] raw = body.split("\n", -1);
        List<Line> lines = new ArrayList<>(raw.length);
        PromptBlock current = null;
        for (int index = 0; index < raw.length; index++) {
            String line = raw[index].endsWith("\r") ? raw[index].substring(0, raw[index].length() - 1) : raw[index];
            int number = index + 1;
            if (line.isEmpty()) {
                lines.add(new Line(number, line, Kind.BLANK, null, null, null));
                continue;
            }
            if (PromptBlock.isHeaderLine(line)) {
                current = PromptBlock.fromSectionKey(line).orElse(null);
                lines.add(new Line(number, line, Kind.HEADER, current, PromptBlock.headerQualifier(line), null));
                continue;
            }
            PromptDictionaryLine entryLine = PromptDictionaryLine.parse(line);
            lines.add(entryLine == null
                    ? new Line(number, line, Kind.OTHER, current, null, null)
                    : new Line(number, line, Kind.ENTRY, current, null, entryLine));
        }
        return new InspectedPrompt(lines, lineFeedsOnly, endsWithLineFeed);
    }
}
