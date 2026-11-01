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

import java.util.Locale;

/**
 * BR-C6 (QF-14): how an allowed past record came to be learned. The store path that writes the record states it under
 * the record's {@code learnedBy} metadata; a record stored before the key existed has none, and is never given one
 * afterwards by a guess.
 */
public enum LearnedBy {

    /** The model's own ALLOW, learned at once: no person verified it and no administrator released it. */
    MODEL_ALLOW,
    /** Learned after the user passed the step-up verification the decision asked for. */
    VERIFIED,
    /** Learned after it waited for promotion (seen on enough days, or vouched for by a verification). */
    PROMOTED,
    /** Learned because an administrator released the stopped request. */
    ADMIN_RELEASE;

    /** The source a metadata value names (a {@code LearnedBy} or its name in any case), or null for any other value. */
    @Nullable
    public static LearnedBy of(@Nullable Object value) {
        if (value instanceof LearnedBy source) {
            return source;
        }
        if (value == null) {
            return null;
        }
        String name = value.toString().strip();
        if (name.isEmpty()) {
            return null;
        }
        try {
            return valueOf(name.toUpperCase(Locale.ROOT));
        }
        catch (IllegalArgumentException unknown) {
            return null;
        }
    }

    /**
     * The source a learned request's {@code verifiedBy} marker stands for: the step-up, the administrator's release or
     * the promotion. Null for no marker or any other value.
     */
    @Nullable
    public static LearnedBy ofVerifiedBy(@Nullable Object verifiedBy) {
        String name = verifiedBy != null ? verifiedBy.toString().strip().toUpperCase(Locale.ROOT) : "";
        return switch (name) {
            case "STEP_UP" -> VERIFIED;
            case "ADMIN_RELEASE" -> ADMIN_RELEASE;
            case "PROMOTED" -> PROMOTED;
            default -> null;
        };
    }
}
