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

import java.util.regex.Pattern;
import org.springframework.util.StringUtils;

import java.util.List;

public class PromptSlotRenderer {

    public String render(List<PromptSlot> slots) {
        if (slots == null || slots.isEmpty()) {
            return "";
        }
        StringBuilder rendered = new StringBuilder();
        for (PromptSlot slot : slots) {
            rendered.append(renderLine(slot));
        }
        return rendered.toString();
    }

    public String renderLine(PromptSlot slot) {
        if (slot == null || !StringUtils.hasText(slot.label()) || !StringUtils.hasText(slot.renderedValue())) {
            return "";
        }
        return slot.label() + ": " + encodeValue(slot.renderedValue()) + "\n";
    }

    /**
     * The value of an untrusted text entry (W3-6): its source, then the text in double quotes, trimmed, its backslashes
     * and quotes escaped so that it cannot close its quotes. A text longer than the limit keeps its first code points
     * and says how many were cut. Line breaks and control characters are escaped when the line is rendered. Null when
     * the text is blank.
     */
    /** An UNTRUSTED TEXT line's value: its source and the quoted text (R1b-3: shared with the prompt inspector). */
    public static final Pattern UNTRUSTED_LINE = Pattern.compile("^source=(.+?); \"(.*)\"$");
    /** The dictionary format of that value. */
    public static final String UNTRUSTED_FORMAT = "source=.+; \".*\"";
    /** The mark a cut text ends with, with the count of the code points cut. */
    public static final Pattern CUT = Pattern.compile("\u2026 \\[\\+(\\d+) chars cut]$");

    public static String untrustedText(String source, String text, int maxCodePoints) {
        if (!StringUtils.hasText(text)) {
            return null;
        }
        String trimmed = text.strip();
        int codePoints = trimmed.codePointCount(0, trimmed.length());
        int limit = Math.max(1, maxCodePoints);
        String kept = trimmed;
        String cut = "";
        if (codePoints > limit) {
            kept = trimmed.substring(0, trimmed.offsetByCodePoints(0, limit));
            cut = "\u2026 [+" + (codePoints - limit) + " chars cut]";
        }
        return "source=" + source + "; \"" + kept.replace("\\", "\\\\").replace("\"", "\\\"") + cut + "\"";
    }

    /**
     * The line form of a value: line breaks, separators and control characters escaped, so that a value stays on its
     * line (R1b-2: shared with the prompt inspector). Null stays null.
     */
    public static String encodeValue(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder encoded = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\r' -> encoded.append("\\r");
                case '\n' -> encoded.append("\\n");
                case '\t' -> encoded.append("\\t");
                case '\u2028' -> encoded.append("\\u2028");
                case '\u2029' -> encoded.append("\\u2029");
                default -> {
                    if (Character.isISOControl(character)) {
                        encoded.append(String.format("\\u%04x", (int) character));
                    } else {
                        encoded.append(character);
                    }
                }
            }
        }
        return encoded.toString();
    }
}
