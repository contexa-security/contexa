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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;

/**
 * The one table a value stored under another vocabulary is read through (W5-7): each classifier accepts its earlier
 * forms as well as raw values, so a stored value read through today's classifier is in today's form. A value today's
 * classifier no longer reads as anything gives null and is left out with its frequency.
 */
public final class VocabularyMigration {

    /** The separator a device is written with ({@code SecuritySemanticNormalizer.device}). */
    private static final String DEVICE_SYSTEM = " on ";

    /** The vocabularies that wrote a login of several methods as its first known method (before W5-10 D6). */
    private static final Set<String> FIRST_METHOD_VOCABULARIES = Set.of(VocabularyVersion.UNSTAMPED, "vocab-2026.10.15");

    /** The values those vocabularies wrote for a login that may have had a second method. */
    private static final Set<String> FIRST_METHOD_ONLY = Set.of("PASSWORD", "PASSKEY");

    private VocabularyMigration() {
    }

    /** A stored network as today's band: a three-octet prefix reads as its /24 band. */
    public static String network(String stored) {
        return SecuritySemanticNormalizer.normalizeNetwork(null, stored);
    }

    /** A stored operating system in today's words; a device class learned as a system gives null. */
    public static String operatingSystem(String stored) {
        return SecuritySemanticNormalizer.normalizeOperatingSystem(stored);
    }

    /**
     * A stored device, a browser on a system, with the system in today's words; a system today's classifier no longer
     * reads leaves the browser alone, as a device of unknown system is written today.
     */
    public static String device(String stored) {
        if (stored == null || stored.isBlank()) {
            return null;
        }
        int separator = stored.lastIndexOf(DEVICE_SYSTEM);
        return separator < 0 ? stored.trim()
                : SecuritySemanticNormalizer.device(stored.substring(0, separator),
                stored.substring(separator + DEVICE_SYSTEM.length()));
    }

    /**
     * A stored login method read from the vocabulary it was stored in (W5-10 D6). The vocabularies before it wrote a
     * login of several methods as its first known method, PASSWORD+ONE_TIME_CODE as PASSWORD and PASSWORD+PASSKEY as
     * PASSKEY: such a stored value is not known to be one factor and reads as nothing. A raw value names its method.
     */
    public static String authenticationType(String stored, String storedVersion) {
        if (stored != null && FIRST_METHOD_ONLY.contains(stored.trim())
                && FIRST_METHOD_VOCABULARIES.contains(VocabularyVersion.of(storedVersion))) {
            return null;
        }
        return authenticationType(stored);
    }

    /** A stored login method in today's words. */
    public static String authenticationType(String stored) {
        return SecuritySemanticNormalizer.normalizeAuthenticationType(stored);
    }

    /** A stored action family by today's name (CREATE and UPDATE are WRITE), the value itself when it names none. */
    public static String actionFamily(String stored) {
        return ActionFamily.nameOrRaw(stored);
    }

    /** A stored resource class in today's four classes (CONFIDENTIAL is SENSITIVE). */
    public static String resourceClass(String stored) {
        return SecuritySemanticNormalizer.normalizeResourceClass(stored);
    }

    /**
     * A past-record document's metadata in today's vocabulary (W5-7 D5): its action family, class, login method,
     * network band and path family read through this table and the version stamped; a value today's classifier no
     * longer reads is removed and the document marked as partly migrated. Other keys stay as they were.
     */
    public static Map<String, Object> pastRecordMetadata(Map<String, Object> stored) {
        Map<String, Object> migrated = stored != null ? new LinkedHashMap<>(stored) : new LinkedHashMap<>();
        boolean partial = false;
        partial |= move(migrated, "actionFamily", VocabularyMigration::actionFamily);
        partial |= move(migrated, "resourceFamily", VocabularyMigration::resourceClass);
        Object storedVersion = migrated.get("vocabularyVersion");
        partial |= move(migrated, "authenticationType",
                value -> authenticationType(value, storedVersion != null ? storedVersion.toString() : null));
        partial |= move(migrated, "ipBand", VocabularyMigration::network);
        partial |= move(migrated, "pathFamily", VocabularyMigration::pathFamily);
        migrated.put("vocabularyVersion", VocabularyVersion.CURRENT);
        if (partial) {
            migrated.put("vocabularyMigrated", "partial");
        }
        return migrated;
    }

    /** Reads one key through the table; true when the value could not move and was removed. */
    private static boolean move(Map<String, Object> metadata, String key, UnaryOperator<String> table) {
        Object value = metadata.get(key);
        if (value == null || value.toString().isBlank()) {
            return false;
        }
        String moved = table.apply(value.toString());
        if (moved == null || moved.isBlank()) {
            metadata.remove(key);
            return true;
        }
        metadata.put(key, moved);
        return false;
    }

    /** A stored path family under today's rule: identifiers generalized, a URL template kept whole. */
    public static String pathFamily(String stored) {
        return SecuritySemanticNormalizer.normalizePathFamily(stored);
    }
}
