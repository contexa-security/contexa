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
 * Only what enforces a decision uses this key. What is recorded about a user (baselines, audit, the blocked user's
 * record) keeps the name as the application gave it. An application whose names differ by case alone turns it off with
 * {@code contexa.security.zerotrust.normalize-user-keys=false}; a restriction of one such user would otherwise reach
 * the other.
 */
public final class ZeroTrustUserKey {

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
        return Normalizer.normalize(userId, Normalizer.Form.NFKC).strip()
                .toUpperCase(Locale.ROOT).toLowerCase(Locale.ROOT);
    }

    private static boolean normalizing() {
        SecurityZeroTrustProperties properties = BOUND.get();
        return properties == null || properties.isNormalizeUserKeys();
    }
}
