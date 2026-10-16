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

/**
 * Why a fact the UNKNOWN block names is not known (dictionary 1.4). A fact that does not apply to the request
 * (not-applicable) is not written at all, so it has no kind here.
 */
public enum PromptUnknownKind {

    /** Nothing gives the fact: the host has no integration for it. */
    NOT_INTEGRATED("not-integrated"),
    /** Its source exists but could not give it for this request (timed out, failed, nothing learned yet). */
    UNAVAILABLE_NOW("unavailable-now");

    /**
     * The prefix of the ID the UNKNOWN line gives each fact it names, U1 onwards in the line's order (N-UID-1, Q-87):
     * the ID MATERIAL_MISSING_EVIDENCE cites. The UNKNOWN line itself carries no line ID.
     */
    public static final String FACT_PREFIX = "U";

    private final String word;

    PromptUnknownKind(String word) {
        this.word = word;
    }

    /** The word the UNKNOWN line writes for the kind. */
    public String word() {
        return word;
    }

    /**
     * The kind the UNKNOWN line writes for a fact the render does not know: unavailable now when its source gave a
     * reason, else not integrated (R1b-3: the one rule the render and the prompt inspector use).
     */
    public static PromptUnknownKind ofReason(String reason) {
        return reason != null ? UNAVAILABLE_NOW : NOT_INTEGRATED;
    }

    /** A reason as the UNKNOWN line writes it: without the spaces around it, or null when it says nothing. */
    public static String reasonText(String reason) {
        return reason == null || reason.isBlank() ? null : reason.trim();
    }

    /**
     * N-UID-1 (Q-87): the UNKNOWN line as a regular expression: each kind once, each name after the ID the line gives
     * it ({@code [U1] ClientSignals}), a reason in brackets after the name (dictionary 1.4, 2.6).
     */
    public static String linePattern() {
        String name = "\\[" + FACT_PREFIX + "[0-9]+\\] [A-Za-z][A-Za-z0-9]*( \\([^()]*\\))?";
        String kind = "(" + wordsPattern() + "): " + name + "(, " + name + ")*";
        return kind + "(; " + kind + ")*";
    }

    /** The words the UNKNOWN line writes, as a regular expression alternation. */
    public static String wordsPattern() {
        StringBuilder words = new StringBuilder();
        for (PromptUnknownKind kind : values()) {
            words.append(words.isEmpty() ? "" : "|").append(kind.word);
        }
        return words.toString();
    }

    /** Whether the UNKNOWN line writes this word for a kind (dictionary 1.4: a fact that does not apply is not written). */
    public static boolean isWord(String word) {
        for (PromptUnknownKind kind : values()) {
            if (kind.word.equals(word)) {
                return true;
            }
        }
        return false;
    }
}
