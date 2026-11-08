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
package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.springframework.lang.Nullable;

import java.text.Normalizer;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The key a user's decisions and restrictions are stored under (Q-18). An application that treats names without regard
 * to case, or to the width of their letters, signs the same person in under each spelling they type and hands Contexa
 * the name as typed, so a BLOCK of {@code plain-k9} would not reach {@code PLAIN-K9}: every spelling of a name reads and
 * writes one key, the Unicode compatibility form without the spaces around it and without case.
 * <p>
 * Only what enforces a decision uses this key. What is recorded about a user (baselines, audit) keeps the name as the
 * application gave it, and so does the blocked user's record, unless the name has the shape of an internal key: that
 * record then holds the key {@link #person} makes. An application whose names differ by case alone turns it off with
 * {@code contexa.security.zerotrust.normalize-user-keys=false}; a restriction of one such user would otherwise reach
 * the other.
 * <p>
 * A console session and an agent acting for a person keep their decisions under keys made from a name
 * ({@code console::<user>}, {@code <user>::agent::<agent id>}). A store takes a key and a name as one string and cannot
 * tell them apart, so a name spelled as such a key is moved off it before it reaches a store: {@link #person} is the key
 * of a name, and whoever hands a store a name hands it that key. Every other name is its own key, so nothing stored
 * under it moves.
 */
public final class ZeroTrustUserKey {

    /** What starts the key of a name spelled as an internal key; the name follows it, spelled out. */
    static final String MOVED_KEY = "ctxa-user::";

    /**
     * What starts the key under which SHADOW mode remembers what it decided for another key. Only what counts decisions
     * (the question whether a user was answered lately) reads it; what enforces a decision never does, so a shadow
     * decision cannot stop anyone, and the decisions of ENFORCE are not mixed with those of an earlier SHADOW.
     */
    public static final String SHADOW_KEY = "shadow::";

    /**
     * The part of an agent's key that marks a name, without the separator before it: a console session of a name that
     * starts so would otherwise spell the key of an agent of the person {@code console}.
     */
    private static final String AGENT_MARK = "agent::";

    private static final AtomicReference<SecurityZeroTrustProperties> BOUND = new AtomicReference<>();

    private ZeroTrustUserKey() {
    }

    /**
     * Binds the setting. The stores and the signals that key by user are built without it, and the same key has to come
     * out of each of them.
     */
    public static void bind(SecurityZeroTrustProperties properties) {
        BOUND.set(properties);
    }

    /** Removes the binding made with the given settings; a binding registered later by another context is kept. */
    public static void unbind(SecurityZeroTrustProperties properties) {
        BOUND.compareAndSet(properties, null);
    }

    /** The key of the given name; null stays null. */
    @Nullable
    public static String of(@Nullable String userId) {
        if (userId == null || !normalizing()) {
            return userId;
        }
        return normalized(userId);
    }

    /**
     * The key of a name that acts for itself: a person, a service client, an agent acting on its own. A name is its own
     * key unless some spelling of it reads as an internal key, whatever the setting says of spellings; such a name is
     * spelled out after {@link #MOVED_KEY}, so that it reaches no console session's or agent's key and, its spellings
     * being one name as for {@link #of}, stays one person. Null stays null.
     * <p>
     * Applied to a name once: a key handed in again is a name of that spelling, and has a key of its own.
     */
    @Nullable
    public static String person(@Nullable String userId) {
        if (userId == null || !internalForm(normalized(userId))) {
            return userId;
        }
        return MOVED_KEY + spelledOut(of(userId).strip());
    }

    private static boolean internalForm(String name) {
        return name.startsWith(ZeroTrustSubject.CONSOLE_KEY) || name.startsWith(MOVED_KEY) || name.startsWith(SHADOW_KEY)
                || name.contains(AGENT_MARK);
    }

    /** The key under which SHADOW mode remembers its decisions for the given key; null stays null. */
    @Nullable
    public static String shadow(@Nullable String key) {
        return key == null ? null : SHADOW_KEY + key;
    }

    /**
     * Keeps what no store folds and no key form uses, and writes each other character as its code: nothing of the name
     * reads as a key form any more, and {@link #of} leaves the result as it is.
     */
    private static String spelledOut(String name) {
        StringBuilder spelled = new StringBuilder(name.length() + 16);
        for (char letter : name.toCharArray()) {
            if (letter >= 'a' && letter <= 'z' || letter >= '0' && letter <= '9'
                    || letter == '-' || letter == '_' || letter == '.') {
                spelled.append(letter);
            } else {
                spelled.append(String.format(Locale.ROOT, "%%%04x", (int) letter));
            }
        }
        return spelled.toString();
    }

    private static String normalized(String userId) {
        return Normalizer.normalize(userId, Normalizer.Form.NFKC).strip()
                .toUpperCase(Locale.ROOT).toLowerCase(Locale.ROOT);
    }

    private static boolean normalizing() {
        SecurityZeroTrustProperties properties = BOUND.get();
        return properties == null || properties.isNormalizeUserKeys();
    }
}
