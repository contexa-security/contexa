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

import org.junit.jupiter.api.Test;
import org.springframework.ai.vectorstore.VectorStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * W6-12 (P6-CHANGE-9): the pgvector lookup names, for the seal, the conditions and the order of its SQL, one entry per
 * condition of the scope and per order key of records(). A change of that SQL changes these words with it.
 */
class PgVectorPastRecordQuerySelectionTest {

    private final PgVectorPastRecordQuery query = new PgVectorPastRecordQuery(mock(VectorStore.class), "public",
            "vector_store");

    @Test
    void theLookupNamesEveryConditionOfItsScope() {
        assertThat(query.filters()).containsExactly(
                "documentType == behavior",
                "userId == scope.userId",
                "retrievalPurpose == scope.retrievalPurpose (when set)",
                "actionFamily == scope.actionFamily",
                "sessionId not in scope.excludedSessionIds",
                "learningState != HELD");
    }

    @Test
    void theLookupNamesTheOrderItShowsTheRecordsIn() {
        assertThat(query.order()).containsExactly(
                "requestPath in firstPaths first",
                "timestamp desc nulls last",
                "id");
    }
}
