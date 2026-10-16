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

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The classifier sources of every vocabulary version (W5-7). A change to a classifier changes what learned data
 * means, so it needs a new version: add it here with its source hash and raise {@link VocabularyVersion#CURRENT}.
 */
class VocabularyVersionTest {

    private static final Map<String, String> SOURCE_HASHES = Map.of(
            "vocab-2026.10.15", "ddafbb0027c6443991ada7f70a4df193228567672938af324fe64a0e8a69b151",
            // W5-10 D6: a login of several methods keeps them all.
            "vocab-2026.10.15.2", "9944fd99888713788b185af6d6c496c17254cb4627f9297d4a1b3292d58f01b7");

    @Test
    void theLoginOfSeveralMethodsIsTheVocabularyAfterTheFirst() {
        assertThat(VocabularyVersion.CURRENT).isEqualTo("vocab-2026.10.15.2");
    }

    @Test
    void theCurrentVersionHoldsTheClassifierSourcesItWasGivenFor() throws IOException {
        StringBuilder sources = new StringBuilder();
        for (String source : VocabularyVersion.SOURCES) {
            sources.append(PromptBundleHashes.normalizeText(
                    Files.readString(Path.of("src/main/java", source), StandardCharsets.UTF_8)));
        }

        assertThat(PromptBundleHashes.sha256Hex(sources.toString()))
                .as("a classifier source changed: give the vocabulary a new version (W5-7)")
                .isEqualTo(SOURCE_HASHES.get(VocabularyVersion.CURRENT));
    }

    @Test
    void aValueWithoutAVersionReadsAsUnstamped() {
        assertThat(VocabularyVersion.of(null)).isEqualTo(VocabularyVersion.UNSTAMPED);
        assertThat(VocabularyVersion.of(" ")).isEqualTo(VocabularyVersion.UNSTAMPED);
        assertThat(VocabularyVersion.isCurrent(VocabularyVersion.CURRENT)).isTrue();
        assertThat(VocabularyVersion.isCurrent(null)).isFalse();
    }
}
