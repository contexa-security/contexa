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
package io.contexa.contexacore.std.rag.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class VectorSearchScopeTest {

    private final FilterExpressionBuilder filter = new FilterExpressionBuilder();

    @Test
    @DisplayName("a filter that names one user is a personal scope wherever the condition sits in the AND chain (W2-15)")
    void aUserConditionInTheAndChainMakesAPersonalScope() {
        Filter.Expression expression = filter.and(
                filter.and(filter.eq("documentType", "behavior"), filter.eq("userId", "alice")),
                filter.nin("sessionId", "session-1")).build();

        VectorSearchScope scope = VectorSearchScope.of(expression);

        assertThat(scope.personal()).isTrue();
        assertThat(scope.userId()).isEqualTo("alice");
        assertThat(scope.unscoped()).isFalse();
    }

    @Test
    @DisplayName("an organisation filter is not personal and names the organisation (W2-15)")
    void anOrganizationConditionNamesTheOrganization() {
        VectorSearchScope scope = VectorSearchScope.of(
                filter.and(filter.eq("documentType", "behavior"), filter.eq("organizationId", "org-1")).build());

        assertThat(scope.personal()).isFalse();
        assertThat(scope.organizationId()).isEqualTo("org-1");
    }

    @Test
    @DisplayName("a user condition under an OR names no single user (W2-15)")
    void aUserConditionUnderAnOrIsNoScope() {
        VectorSearchScope scope = VectorSearchScope.of(
                filter.or(filter.eq("userId", "alice"), filter.eq("userId", "bob")).build());

        assertThat(scope.personal()).isFalse();
        assertThat(scope.userId()).isNull();
        assertThat(scope.unscoped()).isTrue();
    }

    @Test
    @DisplayName("a search without a filter is unscoped (W2-15)")
    void noFilterIsUnscoped() {
        assertThat(VectorSearchScope.of(null).unscoped()).isTrue();
    }

    @Test
    @DisplayName("a written document reaches its user's, its organisation's and unscoped searches only (W2-15)")
    void aWrittenDocumentReachesTheSearchesItCanChange() {
        VectorSearchScope written = VectorSearchScope.ofDocument(
                new Document("record", Map.of("userId", "alice", "organizationId", "org-1")));

        assertThat(written.reaches(VectorSearchScope.of(filter.eq("userId", "alice").build()))).isTrue();
        assertThat(written.reaches(VectorSearchScope.of(filter.eq("userId", "bob").build()))).isFalse();
        assertThat(written.reaches(VectorSearchScope.of(filter.eq("organizationId", "org-1").build()))).isTrue();
        assertThat(written.reaches(VectorSearchScope.of(filter.eq("organizationId", "org-2").build()))).isFalse();
        assertThat(written.reaches(VectorSearchScope.of(filter.eq("documentType", "behavior").build()))).isTrue();
        assertThat(written.reaches(VectorSearchScope.of(null))).isTrue();
    }

    @Test
    @DisplayName("a document without a user or an organisation reaches every search (W2-15)")
    void aDocumentWithoutAScopeReachesEverySearch() {
        VectorSearchScope written = VectorSearchScope.ofDocument(new Document("record", Map.of("documentType", "policy")));

        assertThat(written.reaches(VectorSearchScope.of(filter.eq("userId", "bob").build()))).isTrue();
    }
}
