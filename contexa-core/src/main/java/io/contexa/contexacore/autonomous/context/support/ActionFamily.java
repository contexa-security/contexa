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

import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The one vocabulary of what a request does. Every place of the engine that names the action of a request reads it
 * through this type, so that one request has one action family in the context, the baseline, the session and the
 * prompt. A value is matched by its whole words (camel case, underscores, hyphens, dots, slashes and spaces separate
 * words, and a word with a trailing plural S is also tried), never by a part of a word.
 */
public enum ActionFamily {

    READ,
    WRITE,
    EXPORT,
    DELETE,
    ADMIN,
    EXECUTE,
    UNKNOWN;

    /** When the words of one value name several families, the riskiest one is the value's family. */
    private static final List<ActionFamily> RISK_ORDER = List.of(EXPORT, DELETE, ADMIN, WRITE, EXECUTE, READ);

    private static final Map<String, ActionFamily> WORDS = words();

    private static final Pattern WORD_BOUNDARY =
            Pattern.compile("[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])");

    /** The family a value names, or null when none of its words names one. */
    @Nullable
    public static ActionFamily of(@Nullable Object rawValue) {
        if (rawValue == null) {
            return null;
        }
        String text = rawValue.toString().trim();
        if (text.isEmpty()) {
            return null;
        }
        String whole = text.toUpperCase(Locale.ROOT);
        for (ActionFamily family : values()) {
            if (family.name().equals(whole)) {
                return family;
            }
        }
        EnumSet<ActionFamily> named = EnumSet.noneOf(ActionFamily.class);
        for (String word : wordsOf(text)) {
            ActionFamily family = WORDS.get(word);
            if (family == null && word.length() > 3 && word.endsWith("S")) {
                family = WORDS.get(word.substring(0, word.length() - 1));
            }
            if (family != null) {
                named.add(family);
            }
        }
        for (ActionFamily family : RISK_ORDER) {
            if (named.contains(family)) {
                return family;
            }
        }
        return null;
    }

    /** The family of the first value that names one, or null. */
    @Nullable
    public static ActionFamily firstOf(Object... rawValues) {
        if (rawValues == null) {
            return null;
        }
        for (Object rawValue : rawValues) {
            ActionFamily family = of(rawValue);
            if (family != null) {
                return family;
            }
        }
        return null;
    }

    /** The name of the family a value names, or the value itself when it names none (kept as it was stated). */
    @Nullable
    public static String nameOrRaw(@Nullable String rawValue) {
        ActionFamily family = of(rawValue);
        if (family != null) {
            return family.name();
        }
        return rawValue != null && !rawValue.isBlank() ? rawValue.trim().toUpperCase(Locale.ROOT) : null;
    }

    static List<String> wordsOf(String text) {
        List<String> words = new ArrayList<>();
        for (String word : WORD_BOUNDARY.split(text)) {
            if (!word.isEmpty()) {
                words.add(word.toUpperCase(Locale.ROOT));
            }
        }
        return words;
    }

    private static Map<String, ActionFamily> words() {
        Map<String, ActionFamily> words = new LinkedHashMap<>();
        put(words, READ, "GET", "HEAD", "OPTIONS", "READ", "VIEW", "LIST", "SEARCH", "FETCH", "DOWNLOAD");
        put(words, WRITE, "POST", "PUT", "PATCH", "WRITE", "CREATE", "UPDATE", "MODIFY", "UPLOAD");
        put(words, EXPORT, "EXPORT");
        put(words, DELETE, "DELETE", "REMOVE", "PURGE");
        put(words, EXECUTE, "EXECUTE", "RUN", "INVOKE");
        put(words, ADMIN, "ADMIN", "ROLE", "PERMISSION", "POLICY", "GRANT", "APPROVE", "ELEVATE");
        return Map.copyOf(words);
    }

    private static void put(Map<String, ActionFamily> words, ActionFamily family, String... names) {
        for (String name : names) {
            words.put(name, family);
        }
    }
}
