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
import java.util.Locale;
import java.util.Optional;

/**
 * The user blocks of the v20 security decision prompt, in their rendering order. Each block that holds citable facts
 * has the prefix of its fact ids.
 */
public enum PromptBlock {

    USER_BASELINE("USER BASELINE", "B"),
    SESSION("SESSION", "S"),
    REQUEST("REQUEST", "R"),
    DECISION_FACTS("DECISION FACTS", "F"),
    PAST_RECORDS("PAST RECORDS", "P"),
    UNKNOWN("UNKNOWN", null),
    UNTRUSTED_TEXT("UNTRUSTED TEXT", null),
    SECOND_PASS("SECOND PASS", null);

    /** The mark either side of a block header's title. */
    private static final String HEADER_MARK = "===";

    private final String title;
    private final String factPrefix;

    PromptBlock(String title, String factPrefix) {
        this.title = title;
        this.factPrefix = factPrefix;
    }

    public String title() {
        return title;
    }

    /** The fact id prefix of the block, or null when its lines are not cited by id. */
    public String factPrefix() {
        return factPrefix;
    }

    /**
     * The block's header line with its line break: {@code === TITLE ===}, or {@code === TITLE (q1; q2) ===} with the
     * qualifiers it was drawn with (R1b-3: the one form the render draws and the prompt inspector reads).
     */
    public String header(List<String> qualifiers) {
        return HEADER_MARK + " " + title + (qualifiers.isEmpty() ? "" : " (" + String.join("; ", qualifiers) + ")")
                + " " + HEADER_MARK + "\n";
    }

    /** Whether a prompt line is a block header as {@link #header} draws it. */
    public static boolean isHeaderLine(String line) {
        return line != null && line.startsWith(HEADER_MARK + " ") && line.endsWith(" " + HEADER_MARK)
                && line.length() > 2 * HEADER_MARK.length() + 2;
    }

    /** The text between the parentheses of a header line, or null when it has none. */
    public static String headerQualifier(String header) {
        int open = header.indexOf('(');
        int close = header.lastIndexOf(')');
        return open >= 0 && close > open ? header.substring(open + 1, close) : null;
    }

    /**
     * The block a section key names: the title itself, a header line ({@code === USER BASELINE (learned; ...) ===})
     * or its inner text. Section keys of other prompts give nothing.
     */
    public static Optional<PromptBlock> fromSectionKey(String sectionKey) {
        if (sectionKey == null) {
            return Optional.empty();
        }
        String key = sectionKey.trim();
        if (key.startsWith(HEADER_MARK)) {
            key = key.substring(HEADER_MARK.length());
        }
        if (key.endsWith(HEADER_MARK)) {
            key = key.substring(0, key.length() - HEADER_MARK.length());
        }
        int qualifier = key.indexOf('(');
        if (qualifier >= 0) {
            key = key.substring(0, qualifier);
        }
        key = key.trim().toUpperCase(Locale.ROOT);
        for (PromptBlock block : values()) {
            if (block.title.equals(key)) {
                return Optional.of(block);
            }
        }
        return Optional.empty();
    }
}
