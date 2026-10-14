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
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The sealed sources the checks read besides the canonical context are read once, when the subject is made (R1b-4):
 * the request facts, the authentication state and the past records; a source sealed but unreadable is named.
 */
class PromptInspectionSourcesTest {

    @Test
    void theSealedSourcesAreReadOnceWhenTheSubjectIsMade() {
        SealedEvidencePackage sealed = SealedEvidencePackage.builder().packageId("p-1")
                .requestFactsJson("{\"requestPath\":\"/api/documents/D-1\"}")
                .authStateJson("{\"authMethod\":\"PASSWORD\"}")
                .ragResultsJson("{\"relatedDocuments\":[{\"eventId\":\"e-1\",\"resourcePath\":\"/api/documents/D-2\"}]}")
                .build();

        PromptInspectionSubject subject = new PromptInspectionSubject(sealed, null, InspectedPrompt.parse(""), Map.of(),
                null);

        PromptInspectionSources sources = subject.sources();
        assertThat(sources.requestFacts()).containsEntry("requestPath", "/api/documents/D-1");
        assertThat(sources.authState()).containsEntry("authMethod", "PASSWORD");
        assertThat(sources.pastRecords()).singleElement()
                .satisfies(record -> assertThat(record.getMetadata()).containsEntry("eventId", "e-1"));
        assertThat(sources.unread()).isEmpty();
    }

    @Test
    void aSealedSourceThatDoesNotReadIsNamedAndLeftEmpty() {
        SealedEvidencePackage sealed = SealedEvidencePackage.builder().packageId("p-2")
                .requestFactsJson("{not json").authStateJson(" ").ragResultsJson("[1,").build();

        PromptInspectionSources sources = PromptInspectionSources.read(sealed);

        assertThat(sources.requestFacts()).isEmpty();
        assertThat(sources.authState()).isEmpty();
        assertThat(sources.pastRecords()).isEmpty();
        assertThat(sources.unread()).containsExactlyInAnyOrder("requestFactsJson", "ragResultsJson");
    }
}
