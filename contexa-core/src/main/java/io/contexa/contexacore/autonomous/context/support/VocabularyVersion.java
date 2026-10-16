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

import java.util.List;

/**
 * The version of the classification vocabulary: the action families, resource classes, path families, networks,
 * operating systems and login methods the classifiers produce (W5-7). Learned and remembered data carry it, so that a
 * value stored under another vocabulary is read through {@link VocabularyMigration}. Raise it whenever a classifier's
 * output changes; a test holds the classifier sources of every version.
 */
public final class VocabularyVersion {

    /** The vocabulary the classifiers produce today. */
    public static final String CURRENT = "vocab-2026.10.15.2";

    /** What data stored before the vocabulary was stamped reads as. */
    public static final String UNSTAMPED = "vocab-unstamped";

    /** The classifier sources the version covers, in the order their hash reads them. */
    public static final List<String> SOURCES = List.of(
            "io/contexa/contexacore/autonomous/context/support/ActionFamily.java",
            "io/contexa/contexacore/autonomous/context/support/ActionFamilyResolver.java",
            "io/contexa/contexacore/autonomous/context/support/SecuritySemanticNormalizer.java");

    private VocabularyVersion() {
    }

    /** The version a stored value carries, UNSTAMPED when it carries none. */
    public static String of(String stored) {
        return stored != null && !stored.isBlank() ? stored.trim() : UNSTAMPED;
    }

    /** Whether a stored value is in today's vocabulary. */
    public static boolean isCurrent(String stored) {
        return CURRENT.equals(of(stored));
    }
}
