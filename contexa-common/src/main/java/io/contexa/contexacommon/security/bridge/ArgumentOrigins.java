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
package io.contexa.contexacommon.security.bridge;

import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * CQ-1 (argument origin): where the values of a protected method's call arguments came from, as the host (the adapter
 * of the agent framework) states it. A protected method may take one {@code ArgumentOrigins} parameter besides its own
 * arguments; the host fills it with one {@link Origin} for each argument value it can place: in the user's request, in
 * the company's records, in the output of a tool the agent read earlier, or made by the agent itself. A method without
 * the parameter is decided exactly as before.
 *
 * <p>The decision states a value of {@link Source#TOOL_OUTPUT} (a value neither the user's request nor the company's
 * records name, which first appeared in a tool's output) as a line of the request, with the sentence of the output the
 * host quotes for it. What that means for the verdict is the model's to judge. The event carries the origins under
 * {@link #KEY} as plain maps ({@link #toPayload(boolean, int)}), so they survive the sealed context's JSON form.</p>
 *
 * @param values the origins, in the order the host gave them
 */
public record ArgumentOrigins(List<Origin> values) {

    /** The event payload key the origins go under; the summary of the call's arguments does not hold them. */
    public static final String KEY = "argumentOrigins";
    /** The most values one line of the request states. */
    public static final int MAX_LINE_VALUES = 3;
    /** The longest quoted sentence of a tool's output, in characters. */
    public static final int MAX_EXCERPT_CHARS = 300;
    /** The longest value the decision states; a longer one is cut and ends with an ellipsis. */
    public static final int MAX_VALUE_CHARS = 200;
    /** The longest argument name or tool name the decision states. */
    public static final int MAX_NAME_CHARS = 100;
    /** The most arguments a record keeps the classification of ({@link #classification()}). */
    public static final int MAX_CLASSIFIED = 20;

    private static final String ARGUMENT = "argument";
    private static final String VALUE = "value";
    private static final String SOURCE = "source";
    private static final String TOOL_NAME = "toolName";
    private static final String EXCERPT = "excerpt";

    public ArgumentOrigins {
        values = values == null ? List.of() : values.stream().filter(Objects::nonNull).toList();
    }

    /** Where a value first appeared. */
    public enum Source {
        /** The user's own request. */
        USER_REQUEST,
        /** The company's records (the host's own data). */
        COMPANY_RECORD,
        /** The output of a tool the agent read earlier, and neither of the two above. */
        TOOL_OUTPUT,
        /** Made by the agent itself. */
        AGENT_GENERATED;

        /** The source a payload value names (a {@code Source} or its name in any case), or null. */
        @Nullable
        public static Source of(@Nullable Object value) {
            if (value instanceof Source source) {
                return source;
            }
            String name = text(value);
            if (name == null) {
                return null;
            }
            try {
                return valueOf(name.toUpperCase(Locale.ROOT));
            }
            catch (IllegalArgumentException unknown) {
                return null;
            }
        }
    }

    /**
     * One argument value and where it came from.
     *
     * @param argument the argument's name (for example {@code recipient})
     * @param value    the value, as the call passes it
     * @param source   where it first appeared; null when the host does not say
     * @param toolName the tool whose output it first appeared in (for a {@link Source#TOOL_OUTPUT} value)
     * @param excerpt  the sentence of that output the value stands in, as the host quotes it
     */
    public record Origin(@Nullable String argument, @Nullable String value, @Nullable Source source,
                         @Nullable String toolName, @Nullable String excerpt) {

        public Origin {
            argument = text(argument);
            value = text(value);
            toolName = text(toolName);
            excerpt = text(excerpt);
        }

        /** A value that first appeared in the output of a tool, with the sentence it stands in. */
        public static Origin toolOutput(String argument, String value, String toolName, @Nullable String excerpt) {
            return new Origin(argument, value, Source.TOOL_OUTPUT, toolName, excerpt);
        }

        /** A value of another source (no tool, no sentence). */
        public static Origin of(String argument, String value, Source source) {
            return new Origin(argument, value, source, null, null);
        }
    }

    public static ArgumentOrigins of(Origin... values) {
        return new ArgumentOrigins(values == null ? List.of() : List.of(values));
    }

    /** The origins a call's arguments hold (the first {@code ArgumentOrigins} among them with a value), or null. */
    @Nullable
    public static ArgumentOrigins in(@Nullable Object[] arguments) {
        if (arguments == null) {
            return null;
        }
        for (Object argument : arguments) {
            if (argument instanceof ArgumentOrigins origins && !origins.values().isEmpty()) {
                return origins;
            }
        }
        return null;
    }

    /**
     * The origins as the event carries them: a list of plain maps ({@code argument}, {@code value}, {@code source},
     * {@code toolName}, {@code excerpt}; a field the host did not give is left out). The values and names are cut to
     * their longest and the excerpt to {@code maxExcerptChars} (at most {@link #MAX_EXCERPT_CHARS}); without
     * {@code quoteExcerpt} no sentence is carried, only the classification.
     */
    public List<Map<String, Object>> toPayload(boolean quoteExcerpt, int maxExcerptChars) {
        int excerptLimit = Math.min(maxExcerptChars, MAX_EXCERPT_CHARS);
        List<Map<String, Object>> payload = new ArrayList<>();
        for (Origin origin : values) {
            if (origin.value() == null) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            put(entry, ARGUMENT, clip(origin.argument(), MAX_NAME_CHARS));
            put(entry, VALUE, clip(origin.value(), MAX_VALUE_CHARS));
            put(entry, SOURCE, origin.source() != null ? origin.source().name() : null);
            put(entry, TOOL_NAME, clip(origin.toolName(), MAX_NAME_CHARS));
            if (quoteExcerpt && excerptLimit > 0) {
                put(entry, EXCERPT, clip(origin.excerpt(), excerptLimit));
            }
            payload.add(entry);
        }
        return payload;
    }

    /**
     * BR-C6 (QF-13): what a record keeps of the origins, the classification of the arguments only: the argument name to
     * the name of its source, by name. No value, no sentence and no tool is in it. An origin without a name or a source
     * is left out; a name given twice keeps {@link Source#TOOL_OUTPUT} when either says so, else the first. At most
     * {@link #MAX_CLASSIFIED} arguments.
     */
    public Map<String, String> classification() {
        Map<String, String> classified = new TreeMap<>();
        for (Origin origin : values) {
            classify(classified, origin.argument(), origin.source());
        }
        return classified;
    }

    /**
     * A classification a record or a held request keeps (argument name to the name of its source) read back as it is
     * stored; a name or a source that is none is left out, so what is read back is again a classification and nothing more.
     */
    public static Map<String, String> classificationFrom(@Nullable Object stored) {
        Map<String, String> classified = new TreeMap<>();
        if (stored instanceof Map<?, ?> map) {
            map.forEach((name, kind) -> classify(classified, text(name), Source.of(kind)));
        }
        return classified;
    }

    private static void classify(Map<String, String> classified, @Nullable String argument, @Nullable Source source) {
        String name = clip(argument, MAX_NAME_CHARS);
        if (name == null || source == null) {
            return;
        }
        String known = classified.get(name);
        if (known == null && classified.size() < MAX_CLASSIFIED) {
            classified.put(name, source.name());
        }
        else if (known != null && source == Source.TOOL_OUTPUT) {
            classified.put(name, source.name());
        }
    }

    /** {@link #classification()} of the origins an event payload holds under {@link #KEY}; empty without any. */
    public static Map<String, String> classificationOf(@Nullable Object payload) {
        ArgumentOrigins origins = fromPayload(payload);
        return origins != null ? origins.classification() : Map.of();
    }

    /**
     * The origins an event payload or a sealed context holds under {@link #KEY}: this type itself, or the list of maps
     * {@link #toPayload(boolean, int)} writes (what JSON turns it into). Null when there are none.
     */
    @Nullable
    public static ArgumentOrigins fromPayload(@Nullable Object payload) {
        if (payload instanceof ArgumentOrigins origins) {
            return origins.values().isEmpty() ? null : origins;
        }
        if (!(payload instanceof Collection<?> items)) {
            return null;
        }
        List<Origin> values = new ArrayList<>();
        for (Object item : items) {
            if (item instanceof Origin origin) {
                values.add(origin);
            }
            else if (item instanceof Map<?, ?> map) {
                values.add(new Origin(text(map.get(ARGUMENT)), text(map.get(VALUE)), Source.of(map.get(SOURCE)),
                        text(map.get(TOOL_NAME)), text(map.get(EXCERPT))));
            }
        }
        return values.isEmpty() ? null : new ArgumentOrigins(values);
    }

    /**
     * The text stripped and, when it has more than {@code maxChars} code points, cut to them with the mark of what was
     * cut ({@code … [+12 chars cut]}), as an untrusted text is cut; null for a blank text or a limit below one.
     */
    @Nullable
    public static String clip(@Nullable String text, int maxChars) {
        String stripped = text(text);
        if (stripped == null || maxChars < 1) {
            return null;
        }
        int codePoints = stripped.codePointCount(0, stripped.length());
        if (codePoints <= maxChars) {
            return stripped;
        }
        return stripped.substring(0, stripped.offsetByCodePoints(0, maxChars))
                + "… [+" + (codePoints - maxChars) + " chars cut]";
    }

    private static void put(Map<String, Object> entry, String key, @Nullable Object value) {
        if (value != null) {
            entry.put(key, value);
        }
    }

    @Nullable
    private static String text(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().strip();
        return text.isEmpty() ? null : text;
    }
}
