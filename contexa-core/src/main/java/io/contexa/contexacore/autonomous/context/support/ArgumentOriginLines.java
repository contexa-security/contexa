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
package io.contexa.contexacore.autonomous.context.support;

import io.contexa.contexacommon.security.bridge.ArgumentOrigins;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotRenderer;
import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * CQ-1 (argument origin): the one place that reads the origins a host gave a protected call from the request's context
 * and writes the fact line of them. The decision fact, the v21 prompt line, the quoted sentences of the UNTRUSTED TEXT
 * block, the response check and the prompt inspector all read here, so they cannot disagree about which values are
 * stated or how.
 *
 * <p>Only a value of {@link ArgumentOrigins.Source#TOOL_OUTPUT} is stated: neither the user's request nor the company's
 * records name it, and it first appeared in the output of a tool the agent read. A value the user, the company or the
 * agent itself accounts for has no line. The line states where the value appeared, never what it means.</p>
 */
public final class ArgumentOriginLines {

    /** What a clause says of a value before it says where the value first appeared. */
    private static final String NOT_NAMED = " is not named in the user's request or in the company's records; it first"
            + " appeared in ";
    /** Between the clauses of the values of one line (a clause holds ';' itself). */
    private static final String SEPARATOR = " | ";
    /** A name or value that is written as it is; any other is quoted, so loose text never reads as part of the line. */
    private static final Pattern PLAIN = Pattern.compile("[\\p{L}\\p{N}_.:@/#+=\\-]{1,200}");

    private ArgumentOriginLines() {
    }

    /**
     * The values of the request that first appeared in a tool's output, at most {@link ArgumentOrigins#MAX_LINE_VALUES},
     * in the order the host gave them, each once, with the names, the value and the sentence cut to their longest. Empty
     * when the host gave none (or only values the user, the company or the agent itself account for).
     */
    public static List<ArgumentOrigins.Origin> toolOutputValues(@Nullable CanonicalSecurityContext context) {
        ArgumentOrigins origins = context != null && context.getAttributes() != null
                ? ArgumentOrigins.fromPayload(context.getAttributes().get(ArgumentOrigins.KEY)) : null;
        if (origins == null) {
            return List.of();
        }
        List<ArgumentOrigins.Origin> stated = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (ArgumentOrigins.Origin origin : origins.values()) {
            if (origin.source() != ArgumentOrigins.Source.TOOL_OUTPUT || origin.value() == null) {
                continue;
            }
            ArgumentOrigins.Origin clipped = new ArgumentOrigins.Origin(
                    ArgumentOrigins.clip(origin.argument(), ArgumentOrigins.MAX_NAME_CHARS),
                    ArgumentOrigins.clip(origin.value(), ArgumentOrigins.MAX_VALUE_CHARS), origin.source(),
                    ArgumentOrigins.clip(origin.toolName(), ArgumentOrigins.MAX_NAME_CHARS),
                    ArgumentOrigins.clip(origin.excerpt(), ArgumentOrigins.MAX_EXCERPT_CHARS));
            if (seen.add(clipped.argument() + "\u0000" + clipped.value())) {
                stated.add(clipped);
            }
            if (stated.size() == ArgumentOrigins.MAX_LINE_VALUES) {
                break;
            }
        }
        return List.copyOf(stated);
    }

    /**
     * {@code recipient US133… is not named in the user's request or in the company's records; it first appeared in the
     * output of read_file, in the text: "…"}: one clause for each value of {@link #toolOutputValues}, joined by
     * {@code " | "}, or null when there is none. The sentence is left out of the clause the host quoted none for. The
     * line holds no control character (they are escaped as a prompt line escapes them), so the fact, the drawn line and
     * the inspector's expectation are the same text.
     */
    @Nullable
    public static String line(@Nullable CanonicalSecurityContext context) {
        List<ArgumentOrigins.Origin> values = toolOutputValues(context);
        if (values.isEmpty()) {
            return null;
        }
        List<String> clauses = new ArrayList<>();
        for (ArgumentOrigins.Origin origin : values) {
            StringBuilder clause = new StringBuilder();
            if (origin.argument() != null) {
                clause.append(token(origin.argument())).append(' ');
            }
            clause.append(token(origin.value())).append(NOT_NAMED)
                    .append(origin.toolName() != null ? "the output of " + token(origin.toolName()) : "an earlier tool output");
            if (origin.excerpt() != null) {
                clause.append(", in the text: ").append(quote(origin.excerpt()));
            }
            clauses.add(clause.toString());
        }
        return PromptSlotRenderer.encodeValue(String.join(SEPARATOR, clauses));
    }

    /**
     * The sentences of the tool output that the line quotes, each once in the order of the values: what the UNTRUSTED TEXT
     * block quotes as the host's quotation of a tool's output. Empty when the line quotes none.
     */
    public static List<String> excerpts(@Nullable CanonicalSecurityContext context) {
        Set<String> excerpts = new LinkedHashSet<>();
        for (ArgumentOrigins.Origin origin : toolOutputValues(context)) {
            if (origin.excerpt() != null) {
                excerpts.add(origin.excerpt());
            }
        }
        return List.copyOf(excerpts);
    }

    /** A name or value as the lines write it: as it is when it is a plain token, else quoted and escaped. */
    public static String token(String text) {
        return PLAIN.matcher(text).matches() ? text : quote(text);
    }

    private static String quote(String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
