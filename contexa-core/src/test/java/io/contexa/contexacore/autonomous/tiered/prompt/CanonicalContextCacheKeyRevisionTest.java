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
package io.contexa.contexacore.autonomous.tiered.prompt;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R4-L6: the canonical context cache key takes its revision from the event's own revision keys only. The former
 * verification revision ({@code officialVerification.revisionNo}) is a trace key nothing sets in the kept code; the
 * event metadata the key hashes already separates any event that carries it, so only the source shows the change.
 */
class CanonicalContextCacheKeyRevisionTest {

    private static final Path SECTIONS = Path.of(
            "src/main/java/io/contexa/contexacore/autonomous/tiered/prompt/SecurityDecisionPromptSections.java");

    @Test
    void theCacheKeyRevisionNoLongerReadsTheVerificationRevision() throws IOException {
        String source = Files.readString(SECTIONS, StandardCharsets.UTF_8);
        String keyMethod = source.substring(source.indexOf("private String canonicalContextCacheKey("),
                source.indexOf("private byte[] snapshotCanonicalContext("));

        assertThat(keyMethod).contains("\"evidenceRevision\"", "\"revisionNo\"", "\"sealedEvidence.revision\"")
                .doesNotContain("officialVerification.revisionNo");
    }
}
