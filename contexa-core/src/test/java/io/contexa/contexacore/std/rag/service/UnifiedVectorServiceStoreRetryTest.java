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

import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.contexa.contexacore.std.rag.properties.VectorStoreRetryProperties;
import io.contexa.contexacore.std.rag.service.FailedDocumentSink.FailedDocument;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * BR-C4 (QF-8): a vector document whose store failed waits for a retry and is stored when the store works again,
 * while the caller of the store sees the failure as before.
 */
class UnifiedVectorServiceStoreRetryTest {

    private final MutableClock clock = new MutableClock();
    private final ManualRetryScheduler scheduler = new ManualRetryScheduler();
    private final FlakyVectorStore store = new FlakyVectorStore();
    private final VectorStoreCacheLayer cacheLayer = mock(VectorStoreCacheLayer.class);
    private final PgVectorStoreProperties properties = new PgVectorStoreProperties();
    private final VectorStoreRetryProperties retryProperties = new VectorStoreRetryProperties();
    private ExecutorService executor;

    @BeforeEach
    void setUp() {
        executor = Executors.newFixedThreadPool(4, runnable -> {
            Thread thread = new Thread(runnable, "retry-test-vector-worker");
            thread.setDaemon(true);
            return thread;
        });
    }

    @AfterEach
    void tearDown() {
        executor.shutdownNow();
    }

    private UnifiedVectorService service() {
        return new UnifiedVectorService(properties, cacheLayer, store, executor, retryProperties, null, clock, scheduler);
    }

    private static Document record(int number, String userId) {
        return new Document("record " + number,
                Map.of("documentType", "behavior", "eventId", "event-" + number, "userId", userId));
    }

    private static String idOf(int number) {
        return UnifiedVectorService.documentId("behavior", "event-" + number);
    }

    private static void expectFailure(Runnable store) {
        assertThat(catchThrowable(store::run)).isInstanceOf(VectorOperations.VectorStoreException.class);
    }

    @Test
    @DisplayName("every document is stored once the store works again, and the counts say how")
    void everyDocumentIsStoredOnceTheStoreWorksAgain() {
        UnifiedVectorService service = service();
        // Five stores fail, then three of the retries fail too, then the store works.
        store.failNext(5 + 3);
        for (int number = 1; number <= 5; number++) {
            Document document = record(number, "alice");
            expectFailure(() -> service.storeDocument(document));
        }

        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(5, 5, 0, 0));
        assertThat(store.rows()).isEmpty();

        scheduler.runUntilIdle(30);

        assertThat(store.rows().keySet()).containsExactlyInAnyOrder(idOf(1), idOf(2), idOf(3), idOf(4), idOf(5));
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(5, 0, 5, 0));
        verify(cacheLayer, times(2)).invalidateAfterWrite(any());
    }

    @Test
    @DisplayName("the caller gets the same failure with the retry on as with it off")
    void theCallerGetsTheSameFailureWithTheRetryOnAsWithItOff() {
        VectorStoreRetryProperties off = new VectorStoreRetryProperties();
        off.setEnabled(false);
        UnifiedVectorService withoutRetry = new UnifiedVectorService(properties, cacheLayer, store, executor, off, null,
                clock, new ManualRetryScheduler());
        UnifiedVectorService withRetry = service();
        store.goDown();

        Throwable before = catchThrowable(() -> withoutRetry.storeDocument(record(1, "alice")));
        Throwable after = catchThrowable(() -> withRetry.storeDocument(record(1, "alice")));
        Throwable batchBefore = catchThrowable(() -> withoutRetry.storeDocuments(List.of(record(2, "alice"))));
        Throwable batchAfter = catchThrowable(() -> withRetry.storeDocuments(List.of(record(2, "alice"))));

        assertThat(after).isInstanceOf(VectorOperations.VectorStoreException.class)
                .hasMessage(before.getMessage())
                .hasMessage("Failed to store document");
        assertThat(after.getCause()).hasMessage(before.getCause().getMessage());
        assertThat(batchAfter).isInstanceOf(VectorOperations.VectorStoreException.class)
                .hasMessage(batchBefore.getMessage())
                .hasMessage("Failed to store document batch");
        assertThat(withRetry.storeFailureStats()).isEqualTo(new StoreFailureStats(2, 2, 0, 0));
        assertThat(withoutRetry.storeFailureStats()).isEqualTo(StoreFailureStats.NONE);
    }

    @Test
    @DisplayName("a batch store queues the failed batch and the batches after it, which the call no longer reaches")
    void aBatchStoreQueuesTheFailedBatchAndTheBatchesAfterIt() {
        properties.setBatchSize(2);
        UnifiedVectorService service = service();
        String thirdId = idOf(3);
        store.rejecting(batch -> batch.get(0).getId().equals(thirdId));
        List<Document> records = new ArrayList<>();
        for (int number = 1; number <= 5; number++) {
            records.add(record(number, "alice"));
        }

        expectFailure(() -> service.storeDocuments(records));

        assertThat(store.rows().keySet()).containsExactlyInAnyOrder(idOf(1), idOf(2));
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(3, 3, 0, 0));

        store.recover();
        scheduler.runUntilIdle(10);

        assertThat(store.rows().keySet()).containsExactlyInAnyOrder(idOf(1), idOf(2), idOf(3), idOf(4), idOf(5));
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(3, 0, 3, 0));
    }

    @Test
    @DisplayName("a document queued twice, and stored again after its retry, leaves one row (the store overwrites by id)")
    void aDocumentStoredAgainLeavesOneRow() {
        UnifiedVectorService service = service();
        store.goDown();
        expectFailure(() -> service.storeDocument(record(1, "alice")));
        expectFailure(() -> service.storeDocument(record(1, "alice")));
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(2, 1, 0, 0));

        store.recover();
        scheduler.runUntilIdle(10);
        service.storeDocument(record(1, "alice"));

        assertThat(store.rows()).hasSize(1).containsKey(idOf(1));
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(2, 0, 1, 0));
    }

    @Test
    @DisplayName("with the retry off nothing is queued, scheduled or counted, and the store behaves as before")
    void withTheRetryOffNothingChanges() throws Exception {
        retryProperties.setEnabled(false);
        UnifiedVectorService service = service();
        store.goDown();

        expectFailure(() -> service.storeDocument(record(1, "alice")));
        expectFailure(() -> service.storeDocuments(List.of(record(2, "alice"))));
        store.recover();
        service.storeDocument(record(3, "alice"));

        assertThat(service.storeFailureStats()).isEqualTo(StoreFailureStats.NONE);
        assertThat(scheduler.delays).isEmpty();
        assertThat(store.rows().keySet()).containsExactly(idOf(3));
        assertThat(service.discardPendingStores("alice")).isZero();
        service.deleteDocuments(List.of(idOf(3)));
        assertThat(store.rows()).isEmpty();
        service.destroy();
        assertThat(scheduler.shutDown).isFalse();
    }

    @Test
    @DisplayName("a busy failure is retried inside the call as before, and nothing waits for a background retry")
    void aBusyFailureIsRetriedInsideTheCallAsBefore() {
        UnifiedVectorService service = service();
        store.failNext(1).failingWith("HTTP 503 - {\"error\":\"server busy, please try again.  maximum pending requests exceeded\"}");

        service.storeDocument(record(1, "alice"));

        assertThat(store.addCalls()).isEqualTo(2);
        assertThat(store.rows().keySet()).containsExactly(idOf(1));
        assertThat(service.storeFailureStats()).isEqualTo(StoreFailureStats.NONE);
        assertThat(scheduler.delays).isEmpty();
    }

    /**
     * QF-8b: a record stored late, by the retry, is told to a listener once the store has it; the original failure, a
     * retry that failed and a store that worked at once tell it nothing.
     */
    @Test
    @DisplayName("a retried-store listener is told the documents a retry stored, after the store has them, and nothing else")
    void aRetriedStoreListenerIsToldTheDocumentsARetryStored() {
        UnifiedVectorService service = service();
        List<List<String>> told = new ArrayList<>();
        List<Boolean> inStoreWhenTold = new ArrayList<>();
        service.addRetriedStoreListener(documents -> {
            told.add(documents.stream().map(Document::getId).toList());
            inStoreWhenTold.add(documents.stream().allMatch(document -> store.rows().containsKey(document.getId())));
        });
        service.storeDocument(record(9, "alice"));
        store.failNext(1 + 2);
        expectFailure(() -> service.storeDocument(record(1, "alice")));
        expectFailure(() -> service.storeDocument(record(2, "alice")));
        assertThat(told).as("the original failures tell nobody").isEmpty();

        scheduler.runPending();
        assertThat(told).as("a retry that failed tells nobody").isEmpty();
        scheduler.runUntilIdle(10);

        assertThat(told.stream().flatMap(List::stream)).containsExactlyInAnyOrder(idOf(1), idOf(2))
                .doesNotContain(idOf(9));
        assertThat(inStoreWhenTold).containsOnly(true);
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(2, 0, 2, 0));
    }

    @Test
    @DisplayName("a retried-store listener that throws leaves the retry counts and the stored rows as they are")
    void aRetriedStoreListenerThatThrowsLeavesTheCounts() {
        UnifiedVectorService service = service();
        service.addRetriedStoreListener(documents -> {
            throw new IllegalStateException("listener broke");
        });
        store.failNext(2);
        expectFailure(() -> service.storeDocument(record(1, "alice")));
        expectFailure(() -> service.storeDocument(record(2, "alice")));

        scheduler.runUntilIdle(10);

        assertThat(store.rows().keySet()).containsExactlyInAnyOrder(idOf(1), idOf(2));
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(2, 0, 2, 0));
    }

    @Test
    @DisplayName("with the retry off a retried-store listener is accepted and never called")
    void withTheRetryOffAListenerIsNeverCalled() {
        retryProperties.setEnabled(false);
        UnifiedVectorService service = service();
        List<Object> told = new ArrayList<>();
        service.addRetriedStoreListener(told::add);
        service.addRetriedStoreListener(null);
        store.failNext(1);
        expectFailure(() -> service.storeDocument(record(1, "alice")));
        service.storeDocument(record(1, "alice"));

        assertThat(told).isEmpty();
    }

    @Test
    @DisplayName("a store that works queues nothing and schedules nothing")
    void aStoreThatWorksQueuesNothing() {
        UnifiedVectorService service = service();

        service.storeDocument(record(1, "alice"));
        service.storeDocuments(List.of(record(2, "alice"), record(3, "alice")));

        assertThat(store.rows()).hasSize(3);
        assertThat(service.storeFailureStats()).isEqualTo(StoreFailureStats.NONE);
        assertThat(scheduler.delays).isEmpty();
    }

    @Test
    @DisplayName("deleting a document by id drops its waiting retry, so it does not come back")
    void deletingADocumentDropsItsWaitingRetry() {
        UnifiedVectorService service = service();
        store.goDown();
        expectFailure(() -> service.storeDocument(record(1, "alice")));
        expectFailure(() -> service.storeDocument(record(2, "alice")));
        int addsBefore = store.addCalls();

        store.recover();
        service.deleteDocuments(List.of(idOf(1)));
        scheduler.runUntilIdle(10);

        assertThat(store.rows().keySet()).containsExactly(idOf(2));
        assertThat(store.addedBatches().subList(addsBefore, store.addCalls())).containsExactly(List.of(idOf(2)));
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(2, 0, 1, 0));
    }

    @Test
    @DisplayName("a purged user's waiting documents are dropped and the other users' are still stored")
    void aPurgedUsersWaitingDocumentsAreDropped() {
        UnifiedVectorService service = service();
        store.goDown();
        expectFailure(() -> service.storeDocument(record(1, "alice")));
        expectFailure(() -> service.storeDocument(record(2, "bob")));
        expectFailure(() -> service.storeDocument(record(3, "alice")));
        PendingStoreUserPurgeContributor contributor = new PendingStoreUserPurgeContributor(service);

        contributor.purge("alice");
        store.recover();
        scheduler.runUntilIdle(10);

        assertThat(contributor.name()).isEqualTo("pending-vector-stores");
        assertThat(store.rows().keySet()).containsExactly(idOf(2));
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(3, 0, 1, 0));
        assertThat(service.discardPendingStores(null)).isZero();
        assertThat(service.discardPendingStores(" ")).isZero();
    }

    @Test
    @DisplayName("a sink that fails does not change what the caller of the store sees")
    void aSinkThatFailsDoesNotChangeWhatTheCallerSees() {
        FailedDocumentSink brokenSink = new InMemoryFailedDocumentSink(10) {
            @Override
            public List<FailedDocument> add(List<FailedDocument> entries) {
                throw new IllegalStateException("outbox table is gone");
            }
        };
        UnifiedVectorService service = new UnifiedVectorService(properties, cacheLayer, store, executor, retryProperties,
                brokenSink, clock, scheduler);
        store.goDown();

        Throwable failure = catchThrowable(() -> service.storeDocument(record(1, "alice")));

        assertThat(failure).isInstanceOf(VectorOperations.VectorStoreException.class)
                .hasMessage("Failed to store document");
        assertThat(failure.getCause()).hasMessageContaining("Connection refused");
        assertThat(scheduler.delays).isEmpty();
    }

    @Test
    @DisplayName("an adopter's own sink holds the waiting documents, and a full one drops the oldest")
    void anAdoptersOwnSinkHoldsTheWaitingDocuments() {
        InMemoryFailedDocumentSink sink = new InMemoryFailedDocumentSink(1);
        UnifiedVectorService service = new UnifiedVectorService(properties, cacheLayer, store, executor, retryProperties,
                sink, clock, scheduler);
        store.goDown();

        expectFailure(() -> service.storeDocument(record(1, "alice")));
        expectFailure(() -> service.storeDocument(record(2, "alice")));

        assertThat(sink.oldest(10)).extracting(FailedDocument::id).containsExactly(idOf(2));
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(2, 1, 0, 1));
    }

    @Test
    @DisplayName("a retry is bound by the store timeout: a store that hangs fails the retry, which tries again later")
    void aRetryIsBoundByTheStoreTimeout() {
        properties.setStoreTimeoutMs(100);
        UnifiedVectorService service = service();
        store.goDown();
        expectFailure(() -> service.storeDocument(record(1, "alice")));
        store.recover().doingDuringAdd(() -> {
            try {
                Thread.sleep(2_000);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted by the timeout");
            }
        });

        scheduler.runPending();

        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(1, 1, 0, 0));
        assertThat(scheduler.delays).containsExactly(Duration.ofSeconds(10), Duration.ofSeconds(20));
        assertThat(store.rows()).isEmpty();

        store.doingDuringAdd(() -> { });
        scheduler.runUntilIdle(5);
        assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(1, 0, 1, 0));
    }

    @Test
    @DisplayName("destroy stops the retry")
    void destroyStopsTheRetry() throws Exception {
        UnifiedVectorService service = service();
        store.goDown();
        expectFailure(() -> service.storeDocument(record(1, "alice")));

        service.destroy();

        assertThat(scheduler.shutDown).isTrue();
        expectFailure(() -> service.storeDocument(record(2, "alice")));
        assertThat(scheduler.delays).hasSize(1);
    }

    @Test
    @DisplayName("on a real scheduler thread a document is stored when the store comes back, and destroy ends the thread")
    void onARealSchedulerThreadADocumentIsStoredWhenTheStoreComesBack() throws Exception {
        VectorStoreRetryProperties fast = new VectorStoreRetryProperties();
        fast.setInitialDelay(Duration.ofMillis(20));
        fast.setMaxDelay(Duration.ofMillis(50));
        UnifiedVectorService service = new UnifiedVectorService(properties, cacheLayer, store, executor,
                PastRecordQuery.unavailable(), fast, null);
        store.goDown();
        expectFailure(() -> service.storeDocument(record(1, "alice")));
        await().pollDelay(Duration.ofMillis(150)).atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(store.addCalls()).isGreaterThan(2));
        assertThat(service.storeFailureStats().pending()).isEqualTo(1);

        store.recover();

        await().atMost(Duration.ofSeconds(5)).untilAsserted(
                () -> assertThat(service.storeFailureStats()).isEqualTo(new StoreFailureStats(1, 0, 1, 0)));
        assertThat(store.rows().keySet()).containsExactly(idOf(1));
        service.destroy();
        int callsAfterDestroy = store.addCalls();
        Thread.sleep(150);
        assertThat(store.addCalls()).isEqualTo(callsAfterDestroy);
    }

    @Test
    @DisplayName("the default scheduler runs on a daemon thread and its thread ends when it is shut down")
    void theDefaultSchedulerRunsOnADaemonThread() throws Exception {
        FailedDocumentRetrier.Scheduler threads = FailedDocumentRetrier.threadScheduler();
        AtomicReference<Thread> ran = new AtomicReference<>();
        threads.schedule(() -> ran.set(Thread.currentThread()), Duration.ofMillis(10));
        await().atMost(Duration.ofSeconds(5)).until(() -> ran.get() != null);
        Thread thread = ran.get();

        assertThat(thread.isDaemon()).isTrue();
        assertThat(thread.getName()).startsWith("contexa-vector-store-retry");
        threads.shutdown();
        await().atMost(Duration.ofSeconds(5)).until(() -> !thread.isAlive());
    }
}
