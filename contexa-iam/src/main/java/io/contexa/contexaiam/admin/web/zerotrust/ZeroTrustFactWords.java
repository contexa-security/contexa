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
package io.contexa.contexaiam.admin.web.zerotrust;

import io.contexa.contexacore.autonomous.context.decision.DecisionFactsResolver;
import org.springframework.context.MessageSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * K122: the words of a fact a reason cites, in the decision detail and its preview. The engine gives the model each
 * fact in its own notation, codes included ({@code action EXPORT against the scope group's actions (READ); category
 * CUSTOMER_RECORDS ...}); the administrator reads the role scope's in plain words of the request's language, an action
 * by its word, a business category by the word a message gives it or else by its code in words ({@code customer
 * records}). The notation the model reads is not changed; a fact or a part this reads no notation of stays as written.
 */
final class ZeroTrustFactWords {

    private static final String F = "zt.console.ui.decision.fact.roleScope.";
    private static final String ACTION_WORD = "zt.console.ui.decision.value.action.";
    private static final String CATEGORY_WORD = "zt.console.ui.decision.value.category.";
    /** The engine's parts of the role scope ({@code DecisionFactsResolver.roleScope}), joined by "; ". */
    private static final String PART_SEPARATOR = "; ";
    /** The parts in words are set apart as the console sets words apart. */
    private static final String SEPARATOR = " · ";
    private static final Pattern ACTION = Pattern.compile(
            "^action (\\S+) (against|outside|within) the scope group's actions \\((.*)\\)$");
    private static final Pattern CATEGORY = Pattern.compile(
            "^category (\\S+) (against|outside|within) the scope group's categories \\((.*)\\)$");
    private static final Pattern PEERS = Pattern.compile("^scope group of ([0-9]+) other users?$");
    private static final String DENIED_ACTION = "action in the scope group's denied actions";
    private static final String DENIED_CATEGORY = "category in the scope group's denied categories";
    private static final String PROVISIONAL = "evidence PROVISIONAL";
    private static final Pattern CODE = Pattern.compile("^[A-Z][A-Z0-9_]*$");

    private final MessageSource messages;
    private final Locale locale;

    ZeroTrustFactWords(MessageSource messages, Locale locale) {
        this.messages = messages;
        this.locale = locale == null ? Locale.ENGLISH : locale;
    }

    /** The fact's value in words; null for none. */
    String words(String factName, String value) {
        if (value == null || value.isBlank() || !DecisionFactsResolver.ROLE_SCOPE.equals(factName)) {
            return value;
        }
        List<String> parts = new ArrayList<>();
        for (String part : value.split(PART_SEPARATOR)) {
            parts.add(roleScopePart(part.trim()));
        }
        return String.join(SEPARATOR, parts);
    }

    private String roleScopePart(String part) {
        Matcher action = ACTION.matcher(part);
        if (action.matches()) {
            return message(F + "action." + action.group(2), part, action(action.group(1)), list(action.group(3), true));
        }
        Matcher category = CATEGORY.matcher(part);
        if (category.matches()) {
            return message(F + "category." + category.group(2), part, category(category.group(1)),
                    list(category.group(3), false));
        }
        Matcher peers = PEERS.matcher(part);
        if (peers.matches()) {
            long count = Long.parseLong(peers.group(1));
            return message(F + (count == 1 ? "peer" : "peers"), part, count);
        }
        return switch (part) {
            case DENIED_ACTION -> message(F + "deniedAction", part);
            case DENIED_CATEGORY -> message(F + "deniedCategory", part);
            case PROVISIONAL -> message(F + "provisional", part);
            default -> part;
        };
    }

    private String list(String values, boolean actions) {
        List<String> words = new ArrayList<>();
        for (String value : values.split(",")) {
            if (!value.isBlank()) {
                words.add(actions ? action(value.trim()) : category(value.trim()));
            }
        }
        return String.join(", ", words);
    }

    private String action(String code) {
        return word(ACTION_WORD, code);
    }

    private String category(String code) {
        return word(CATEGORY_WORD, code);
    }

    /** A code by the word a message gives it, else in words: {@code CUSTOMER_RECORDS} reads as customer records. */
    private String word(String prefix, String code) {
        String word = messages == null ? ""
                : messages.getMessage(prefix + code.toUpperCase(Locale.ROOT), null, "", locale);
        if (word != null && !word.isEmpty()) {
            return word;
        }
        return CODE.matcher(code).matches() ? code.toLowerCase(Locale.ROOT).replace('_', ' ') : code;
    }

    private String message(String key, String fallback, Object... args) {
        return messages == null ? fallback : messages.getMessage(key, args, fallback, locale);
    }
}
