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

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Values stored under an earlier vocabulary read in today's form through one table (W5-7). */
class VocabularyMigrationTest {

    @Test
    void aStoredDeviceKeepsItsBrowserAndReadsItsSystemInTodaysWords() {
        // W5-7 D4: a device is a browser on a system; the system is read through today's classifier, and a system it
        // no longer reads leaves the browser alone, as a device of unknown system is read today.
        assertThat(VocabularyMigration.device("Chrome/140 on Windows 11")).isEqualTo("Chrome/140 on WINDOWS");
        assertThat(VocabularyMigration.device("Chrome/140 on WINDOWS")).isEqualTo("Chrome/140 on WINDOWS");
        assertThat(VocabularyMigration.device("Chrome/140 on DESKTOP")).isEqualTo("Chrome/140");
        assertThat(VocabularyMigration.device("Chrome/140")).isEqualTo("Chrome/140");
    }

    @Test
    void aStoredNetworkReadsAsTodaysBand() {
        assertThat(VocabularyMigration.network("10.40.12")).isEqualTo("10.40.12.0/24");
        assertThat(VocabularyMigration.network("10.40.12.0/24")).isEqualTo("10.40.12.0/24");
    }

    @Test
    void aStoredOperatingSystemReadsInTodaysWordsAndADeviceClassIsLeftOut() {
        assertThat(VocabularyMigration.operatingSystem("Windows")).isEqualTo("WINDOWS");
        assertThat(VocabularyMigration.operatingSystem("DESKTOP")).isNull();
    }

    @Test
    void aStoredPasswordOfAVocabularyThatKeptOnlyTheFirstMethodIsNotKnownToBeOneFactor() {
        // W5-10 D6: before it, a login of several methods was written as its first known method (PASSWORD+ONE_TIME_CODE
        // as PASSWORD, PASSWORD+PASSKEY as PASSKEY); the number of factors of such a stored value is not known.
        assertThat(VocabularyMigration.authenticationType("PASSWORD", "vocab-2026.10.15")).isNull();
        assertThat(VocabularyMigration.authenticationType("PASSKEY", null)).isNull();
        assertThat(VocabularyMigration.authenticationType("ONE_TIME_CODE", "vocab-2026.10.15")).isEqualTo("ONE_TIME_CODE");
        // A raw login value names its one method; only the classifier's own output lost a factor.
        assertThat(VocabularyMigration.authenticationType("UsernamePasswordAuthenticationToken", null))
                .isEqualTo("PASSWORD");
        assertThat(VocabularyMigration.authenticationType("PASSWORD", VocabularyVersion.CURRENT)).isEqualTo("PASSWORD");
        assertThat(VocabularyMigration.pastRecordMetadata(Map.of("authenticationType", "PASSWORD",
                "vocabularyVersion", "vocab-2026.10.15")))
                .doesNotContainKey("authenticationType")
                .containsEntry("vocabularyMigrated", "partial");
    }

    @Test
    void aStoredLoginMethodReadsInTodaysWords() {
        assertThat(VocabularyMigration.authenticationType("UsernamePasswordAuthenticationToken")).isEqualTo("PASSWORD");
    }

    @Test
    void aStoredActionFamilyReadsByTodaysName() {
        assertThat(VocabularyMigration.actionFamily("CREATE")).isEqualTo("WRITE");
        assertThat(VocabularyMigration.actionFamily("update")).isEqualTo("WRITE");
        assertThat(VocabularyMigration.actionFamily("EXPORT")).isEqualTo("EXPORT");
    }

    @Test
    void aStoredResourceClassReadsInTodaysFourClasses() {
        assertThat(VocabularyMigration.resourceClass("CONFIDENTIAL")).isEqualTo("SENSITIVE");
        assertThat(VocabularyMigration.resourceClass("CRITICAL")).isEqualTo("CRITICAL");
    }

    @Test
    void aStoredPastRecordReadsInTodaysVocabularyAndSaysWhatCouldNotMove() {
        Map<String, Object> stored = new HashMap<>(Map.of(
                "actionFamily", "CREATE",
                "resourceFamily", "CONFIDENTIAL",
                "authenticationType", "UsernamePasswordAuthenticationToken",
                "ipBand", "10.40.12",
                "pathFamily", "/api/projects/123/exports",
                "userId", "alice"));

        Map<String, Object> migrated = VocabularyMigration.pastRecordMetadata(stored);

        assertThat(migrated)
                .containsEntry("actionFamily", "WRITE")
                .containsEntry("resourceFamily", "SENSITIVE")
                .containsEntry("authenticationType", "PASSWORD")
                .containsEntry("ipBand", "10.40.12.0/24")
                .containsEntry("pathFamily", "/api/projects/{id}/exports/*")
                .containsEntry("userId", "alice")
                .containsEntry("vocabularyVersion", VocabularyVersion.CURRENT)
                .doesNotContainKey("vocabularyMigrated");
        assertThat(VocabularyMigration.pastRecordMetadata(Map.of("resourceFamily", "WHATEVER")))
                .doesNotContainKey("resourceFamily")
                .containsEntry("vocabularyMigrated", "partial");
    }

    @Test
    void aStoredPathFamilyReadsUnderTodaysRule() {
        assertThat(VocabularyMigration.pathFamily("/api/projects/123/exports")).isEqualTo("/api/projects/{id}/exports/*");
        assertThat(VocabularyMigration.pathFamily("/api/projects/{projectKey}/exports"))
                .isEqualTo("/api/projects/{projectKey}/exports");
    }
}
