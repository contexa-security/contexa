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

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A resource has a class (its sensitivity grade) and a business category, two vocabularies that never stand for each
 * other (W2-10, S-2).
 */
class ResourceClassAndCategoryTest {

    @Test
    void aCategoryIsTheHostsNameAsAToken() {
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory("project documents")).isEqualTo("PROJECT_DOCUMENTS");
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory("audit-log")).isEqualTo("AUDIT_LOG");
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory("PUBLIC_RELEASES")).isEqualTo("PUBLIC_RELEASES");
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory("HIGH_VALUE_EXPORTS")).isEqualTo("HIGH_VALUE_EXPORTS");
    }

    @Test
    void aValueMadeOnlyOfClassWordsIsNoCategory() {
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory("CRITICAL")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory("high")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory("Confidential")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory("public low")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory("UNKNOWN")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory(" ", null)).isNull();
    }

    @Test
    void aClassWordIsPassedOverForTheNextValue() {
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory("RESTRICTED", "REPORT")).isEqualTo("REPORT");
        assertThat(SecuritySemanticNormalizer.normalizeResourceCategory(null, "SENSITIVE", "audit log")).isEqualTo("AUDIT_LOG");
    }

    @Test
    void theClassIsTheContextsFieldElseTheClassificationValues() {
        CanonicalSecurityContext.Resource stated = CanonicalSecurityContext.Resource.builder()
                .resourceClass("SENSITIVE")
                .sensitivity("LOW")
                .build();
        CanonicalSecurityContext.Resource classified = CanonicalSecurityContext.Resource.builder()
                .sensitivity("RESTRICTED")
                .resourceType("REPORT")
                .build();

        assertThat(SecuritySemanticNormalizer.resourceClassOf(stated)).isEqualTo("SENSITIVE");
        assertThat(SecuritySemanticNormalizer.resourceClassOf(classified)).isEqualTo("CRITICAL");
        assertThat(SecuritySemanticNormalizer.resourceClassOf(null)).isNull();
    }

    @Test
    void aCategoryNeverDecidesTheClass() {
        CanonicalSecurityContext.Resource resource = CanonicalSecurityContext.Resource.builder()
                .resourceCategory("PUBLIC_RELEASES")
                .build();

        assertThat(SecuritySemanticNormalizer.resourceClassOf(resource)).isNull();
    }
}
