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

import io.contexa.contexacore.std.rag.service.FailedDocumentSink.FailedDocument;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryFailedDocumentSinkTest {

    private static final Instant T0 = Instant.parse("2026-10-29T00:00:00Z");

    private static FailedDocument entry(String id) {
        return entry(id, "text of " + id);
    }

    private static FailedDocument entry(String id, String text) {
        return new FailedDocument(Document.builder().id(id).text(text).metadata(Map.of("userId", "u")).build(), T0, 0);
    }

    private static List<String> ids(List<FailedDocument> entries) {
        return entries.stream().map(FailedDocument::id).toList();
    }

    @Test
    @DisplayName("entries wait in the order they came, and oldest hands out a copy that leaves them in the sink")
    void entriesWaitInTheOrderTheyCame() {
        InMemoryFailedDocumentSink sink = new InMemoryFailedDocumentSink(10);

        assertThat(sink.add(List.of(entry("a"), entry("b"), entry("c")))).isEmpty();

        assertThat(sink.size()).isEqualTo(3);
        assertThat(ids(sink.oldest(2))).containsExactly("a", "b");
        assertThat(ids(sink.oldest(10))).containsExactly("a", "b", "c");
        assertThat(sink.size()).isEqualTo(3);
    }

    @Test
    @DisplayName("a full sink pushes out the oldest entries and says which they were")
    void aFullSinkPushesOutTheOldestEntries() {
        InMemoryFailedDocumentSink sink = new InMemoryFailedDocumentSink(3);
        sink.add(List.of(entry("a"), entry("b"), entry("c")));

        List<FailedDocument> pushedOut = sink.add(List.of(entry("d"), entry("e")));

        assertThat(ids(pushedOut)).containsExactly("a", "b");
        assertThat(ids(sink.oldest(10))).containsExactly("c", "d", "e");
        assertThat(sink.size()).isEqualTo(3);
    }

    @Test
    @DisplayName("a document that already waits is replaced, not added twice (the store overwrites by id)")
    void aDocumentThatAlreadyWaitsIsReplaced() {
        InMemoryFailedDocumentSink sink = new InMemoryFailedDocumentSink(10);
        sink.add(List.of(entry("a", "first"), entry("b")));

        List<FailedDocument> pushedOut = sink.add(List.of(entry("a", "second")));

        assertThat(pushedOut).isEmpty();
        assertThat(sink.size()).isEqualTo(2);
        assertThat(sink.oldest(10)).extracting(waiting -> waiting.document().getText()).containsExactly("second", "text of b");
    }

    @Test
    @DisplayName("requeue moves an entry behind the others with its new state, and does not bring back a removed one")
    void requeueMovesAnEntryBehindTheOthers() {
        InMemoryFailedDocumentSink sink = new InMemoryFailedDocumentSink(10);
        FailedDocument a = entry("a");
        sink.add(List.of(a, entry("b"), entry("c")));

        sink.requeue(List.of(a.afterFailedAttempt(), entry("gone")));

        assertThat(ids(sink.oldest(10))).containsExactly("b", "c", "a");
        assertThat(sink.oldest(10).get(2).attempts()).isEqualTo(1);
        assertThat(sink.size()).isEqualTo(3);
    }

    @Test
    @DisplayName("removeWhere removes the entries the condition accepts and returns them")
    void removeWhereRemovesAndReturnsTheAcceptedEntries() {
        InMemoryFailedDocumentSink sink = new InMemoryFailedDocumentSink(10);
        sink.add(List.of(entry("a"), entry("b"), entry("c")));

        List<FailedDocument> removed = sink.removeWhere(waiting -> !waiting.id().equals("b"));

        assertThat(ids(removed)).containsExactly("a", "c");
        assertThat(ids(sink.oldest(10))).containsExactly("b");
        assertThat(sink.removeWhere(waiting -> false)).isEmpty();
    }

    @Test
    @DisplayName("a capacity below one still holds one entry")
    void aCapacityBelowOneStillHoldsOneEntry() {
        InMemoryFailedDocumentSink sink = new InMemoryFailedDocumentSink(0);

        List<FailedDocument> pushedOut = sink.add(List.of(entry("a"), entry("b")));

        assertThat(ids(pushedOut)).containsExactly("a");
        assertThat(ids(sink.oldest(10))).containsExactly("b");
    }
}
