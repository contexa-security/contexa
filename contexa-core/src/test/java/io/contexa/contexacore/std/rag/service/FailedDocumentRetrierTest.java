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

import io.contexa.contexacore.std.rag.properties.VectorStoreRetryProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;

/** The retry of failed vector stores (BR-C4, QF-8), driven by hand: a manual scheduler, a clock the test moves. */
class FailedDocumentRetrierTest {

    private final MutableClock clock = new MutableClock();
    private final ManualRetryScheduler scheduler = new ManualRetryScheduler();
    private final VectorStoreRetryProperties properties = new VectorStoreRetryProperties();
    /** The ids of every try of the store, whether it failed or not. */
    private final List<List<String>> tries = new ArrayList<>();
    private final List<String> stored = new ArrayList<>();
    private final List<List<String>> deletedAgain = new ArrayList<>();
    private Predicate<List<Document>> storeFails = batch -> false;
    private Runnable duringStore = () -> { };
    private FailedDocumentRetrier retrier;

    private FailedDocumentRetrier retrier() {
        retrier = new FailedDocumentRetrier(properties, new InMemoryFailedDocumentSink(properties.getQueueSize()),
                clock, scheduler, this::store, deletedAgain::add);
        return retrier;
    }

    private void store(List<Document> batch) {
        tries.add(batch.stream().map(Document::getId).toList());
        duringStore.run();
        if (storeFails.test(batch)) {
            throw new RuntimeException("Connection refused");
        }
        batch.forEach(document -> stored.add(document.getId()));
    }

    private static Document document(String id) {
        return Document.builder().id(id).text("text of " + id).metadata(Map.of("userId", "u-" + id)).build();
    }

    private static List<Document> documents(String... ids) {
        List<Document> documents = new ArrayList<>();
        for (String id : ids) {
            documents.add(document(id));
        }
        return documents;
    }

    private static Predicate<List<Document>> failingTimes(int times) {
        AtomicInteger left = new AtomicInteger(times);
        return batch -> left.getAndDecrement() > 0;
    }

    @Test
    @DisplayName("the first retry comes after the initial delay, and several failures schedule one retry")
    void theFirstRetryComesAfterTheInitialDelay() {
        retrier();

        retrier.enqueue(documents("a"));
        retrier.enqueue(documents("b"));

        assertThat(scheduler.delays).containsExactly(Duration.ofSeconds(10));
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(2, 2, 0, 0));
        assertThat(tries).isEmpty();
    }

    @Test
    @DisplayName("documents are all stored once the store works again, after retries at 10, 20, 40, 80 seconds")
    void documentsAreAllStoredOnceTheStoreWorksAgain() {
        storeFails = failingTimes(3);
        retrier();
        retrier.enqueue(documents("a", "b", "c"));

        scheduler.runUntilIdle(20);

        assertThat(stored).containsExactlyInAnyOrder("a", "b", "c");
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(3, 0, 3, 0));
        // 10 s to the first retry, then double after each failed retry; a quarter second between the batches that drain.
        assertThat(scheduler.delays).containsExactly(Duration.ofSeconds(10), Duration.ofSeconds(20),
                Duration.ofSeconds(40), Duration.ofSeconds(80), Duration.ofMillis(250));
    }

    @Test
    @DisplayName("the delay stops growing at the longest wait of five minutes")
    void theDelayStopsGrowingAtTheLongestWait() {
        storeFails = batch -> true;
        properties.setMaxAttempts(1000);
        properties.setMaxAge(Duration.ofDays(1));
        retrier();
        retrier.enqueue(documents("a"));

        for (int i = 0; i < 9; i++) {
            scheduler.runPending();
        }

        assertThat(scheduler.delays).containsExactly(
                Duration.ofSeconds(10), Duration.ofSeconds(20), Duration.ofSeconds(40), Duration.ofSeconds(80),
                Duration.ofSeconds(160), Duration.ofMinutes(5), Duration.ofMinutes(5), Duration.ofMinutes(5),
                Duration.ofMinutes(5), Duration.ofMinutes(5));
    }

    @Test
    @DisplayName("while retries fail the batch is halved, and after they succeed it grows back")
    void theBatchIsHalvedWhileRetriesFailAndGrowsBack() {
        properties.setBatchSize(8);
        storeFails = failingTimes(3);
        retrier();
        retrier.enqueue(documents("1", "2", "3", "4", "5", "6", "7", "8"));

        scheduler.runUntilIdle(30);

        assertThat(tries).extracting(List::size).containsExactly(8, 4, 2, 1, 2, 4, 1);
        assertThat(stored).hasSize(8).doesNotHaveDuplicates();
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(8, 0, 8, 0));
    }

    @Test
    @DisplayName("a document is given up after the most tries, with an error logged and the drop counted")
    void aDocumentIsGivenUpAfterTheMostTries() {
        storeFails = batch -> true;
        properties.setMaxAttempts(3);
        retrier();
        retrier.enqueue(documents("a"));

        int runs = scheduler.runUntilIdle(20);

        assertThat(runs).isEqualTo(3);
        assertThat(tries).hasSize(3);
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(1, 0, 0, 1));
        assertThat(scheduler.hasPending()).isFalse();
    }

    @Test
    @DisplayName("a document older than the longest age is given up without another try, a younger one is still tried")
    void aDocumentOlderThanTheLongestAgeIsGivenUp() {
        properties.setMaxAge(Duration.ofHours(1));
        retrier();
        retrier.enqueue(documents("old"));
        clock.advance(Duration.ofMinutes(40));
        retrier.enqueue(documents("young"));
        clock.advance(Duration.ofMinutes(21));

        scheduler.runPending();

        assertThat(tries).containsExactly(List.of("young"));
        assertThat(stored).containsExactly("young");
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(2, 0, 1, 1));
    }

    @Test
    @DisplayName("a full queue pushes out the oldest documents and counts them as dropped")
    void aFullQueuePushesOutTheOldestDocuments() {
        properties.setQueueSize(3);
        retrier();

        retrier.enqueue(documents("a", "b"));
        retrier.enqueue(documents("c", "d", "e"));

        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(5, 3, 0, 2));
        scheduler.runUntilIdle(10);
        assertThat(stored).containsExactlyInAnyOrder("c", "d", "e");
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(5, 0, 3, 2));
    }

    @Test
    @DisplayName("failed always equals retried plus dropped plus pending")
    void theCountsAddUp() {
        properties.setQueueSize(4);
        properties.setBatchSize(4);
        properties.setMaxAttempts(3);
        storeFails = batch -> batch.stream().anyMatch(document -> document.getId().equals("poison"));
        retrier();
        // Two documents are pushed out at once (a, b); the poison one is given up after its third failed try.
        retrier.enqueue(documents("a", "b", "poison", "c", "d", "e"));

        for (int i = 0; i < 20 && scheduler.hasPending(); i++) {
            scheduler.runPending();
            StoreFailureStats stats = retrier.stats();
            assertThat(stats.failed()).isEqualTo(stats.retried() + stats.dropped() + stats.pending());
        }

        assertThat(retrier.stats().dropped()).isPositive();
        assertThat(retrier.stats().retried()).isPositive();
    }

    @Test
    @DisplayName("a document that never stores does not hold back the others waiting behind it")
    void aDocumentThatNeverStoresDoesNotHoldBackTheOthers() {
        properties.setBatchSize(4);
        properties.setMaxAttempts(8);
        storeFails = batch -> batch.stream().anyMatch(document -> document.getId().equals("poison"));
        retrier();
        retrier.enqueue(documents("poison", "a", "b", "c"));

        scheduler.runUntilIdle(50);

        assertThat(stored).containsExactlyInAnyOrder("a", "b", "c");
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(4, 0, 3, 1));
    }

    @Test
    @DisplayName("a document queued twice waits once and is stored once")
    void aDocumentQueuedTwiceWaitsOnce() {
        retrier();

        retrier.enqueue(documents("a"));
        retrier.enqueue(documents("a"));
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(2, 1, 0, 0));

        scheduler.runUntilIdle(10);
        assertThat(stored).containsExactly("a");
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(2, 0, 1, 0));
    }

    @Test
    @DisplayName("a document discarded while it waits is never stored and is not counted as dropped")
    void aDocumentDiscardedWhileItWaitsIsNeverStored() {
        retrier();
        retrier.enqueue(documents("a", "b"));

        int discarded = retrier.discard(document -> document.getId().equals("a"));
        scheduler.runUntilIdle(10);

        assertThat(discarded).isEqualTo(1);
        assertThat(tries).containsExactly(List.of("b"));
        assertThat(stored).containsExactly("b");
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(2, 0, 1, 0));
    }

    @Test
    @DisplayName("a document discarded while its store runs is deleted again once the store has written it")
    void aDocumentDiscardedWhileItsStoreRunsIsDeletedAgain() {
        retrier();
        retrier.enqueue(documents("a", "b"));
        duringStore = () -> retrier.discard(document -> document.getId().equals("a"));

        scheduler.runUntilIdle(10);

        assertThat(stored).containsExactlyInAnyOrder("a", "b");
        assertThat(deletedAgain).containsExactly(List.of("a"));
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(2, 0, 1, 0));
    }

    @Test
    @DisplayName("a failing delete of a purged document does not stop the retry")
    void aFailingDeleteOfAPurgedDocumentDoesNotStopTheRetry() {
        FailedDocumentRetrier failingDelete = new FailedDocumentRetrier(properties,
                new InMemoryFailedDocumentSink(properties.getQueueSize()), clock, scheduler, this::store, ids -> {
                    throw new IllegalStateException("store down");
                });
        failingDelete.enqueue(documents("a", "b"));
        duringStore = () -> failingDelete.discard(document -> document.getId().equals("a"));

        scheduler.runUntilIdle(10);

        assertThat(failingDelete.stats()).isEqualTo(new StoreFailureStats(2, 0, 1, 0));
    }

    @Test
    @DisplayName("a stored listener is told the documents a retry stored, once, and only after the retry succeeded")
    void aStoredListenerIsToldTheDocumentsARetryStoredAndOnlyAfterItSucceeded() {
        storeFails = failingTimes(2);
        List<List<String>> told = new ArrayList<>();
        List<Integer> storedWhenTold = new ArrayList<>();
        retrier();
        retrier.addStoredListener(documents -> {
            told.add(documents.stream().map(Document::getId).toList());
            storedWhenTold.add(stored.size());
        });
        retrier.enqueue(documents("a", "b"));

        scheduler.runPending();
        scheduler.runPending();
        assertThat(told).as("two failed retries tell nobody").isEmpty();
        scheduler.runUntilIdle(10);

        assertThat(told).containsExactly(List.of("a", "b"));
        assertThat(storedWhenTold).as("told after the store had the documents").containsExactly(2);
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(2, 0, 2, 0));
    }

    @Test
    @DisplayName("a document queued and never stored, or given up, is never told")
    void aDocumentGivenUpIsNeverTold() {
        storeFails = batch -> true;
        properties.setMaxAttempts(2);
        List<String> told = new ArrayList<>();
        retrier();
        retrier.addStoredListener(documents -> documents.forEach(document -> told.add(document.getId())));
        retrier.enqueue(documents("a"));

        scheduler.runUntilIdle(10);

        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(1, 0, 0, 1));
        assertThat(told).isEmpty();
    }

    @Test
    @DisplayName("a document discarded while its store runs is not told as stored")
    void aDocumentDiscardedWhileItsStoreRunsIsNotTold() {
        List<String> told = new ArrayList<>();
        retrier();
        retrier.addStoredListener(documents -> documents.forEach(document -> told.add(document.getId())));
        retrier.enqueue(documents("a", "b"));
        duringStore = () -> retrier.discard(document -> document.getId().equals("a"));

        scheduler.runUntilIdle(10);

        assertThat(told).containsExactly("b");
    }

    @Test
    @DisplayName("a listener that throws changes no count, stops no other listener and does not stop the retry")
    void aListenerThatThrowsChangesNoCount() {
        List<String> told = new ArrayList<>();
        retrier();
        retrier.addStoredListener(documents -> {
            throw new IllegalStateException("listener broke");
        });
        retrier.addStoredListener(documents -> documents.forEach(document -> told.add(document.getId())));
        retrier.enqueue(documents("a", "b"));

        scheduler.runUntilIdle(10);

        assertThat(told).containsExactlyInAnyOrder("a", "b");
        assertThat(stored).containsExactlyInAnyOrder("a", "b");
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(2, 0, 2, 0));
    }

    @Test
    @DisplayName("after the queue emptied, a new failure waits the initial delay again")
    void afterTheQueueEmptiedANewFailureWaitsTheInitialDelayAgain() {
        storeFails = batch -> true;
        properties.setMaxAttempts(2);
        retrier();
        retrier.enqueue(documents("a"));
        scheduler.runUntilIdle(10);
        assertThat(retrier.stats().dropped()).isEqualTo(1);

        retrier.enqueue(documents("b"));

        assertThat(scheduler.delays.get(scheduler.delays.size() - 1)).isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    @DisplayName("after shutdown nothing is scheduled any more, and the stats stay readable")
    void afterShutdownNothingIsScheduledAnyMore() {
        retrier();
        retrier.enqueue(documents("a"));

        retrier.shutdown();
        retrier.enqueue(documents("b"));

        assertThat(scheduler.shutDown).isTrue();
        assertThat(scheduler.delays).hasSize(1);
        assertThat(retrier.stats()).isEqualTo(new StoreFailureStats(2, 2, 0, 0));
    }
}
