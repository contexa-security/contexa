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
import io.contexa.contexacore.std.rag.service.FailedDocumentSink.FailedDocument;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * Keeps the documents whose vector store failed and stores them again in the background (BR-C4, QF-8).
 * <p>
 * One scheduled task at a time takes the oldest waiting documents in a batch and stores them. A batch that is stored
 * leaves the queue; a batch that fails stays, moved behind the others so that one document the store keeps refusing
 * does not hold back the rest. While retries fail the wait between them doubles (from the initial delay up to the
 * longest) and the batch is halved, so that a store that is down is not pressed; after a retry succeeds the batch
 * grows back and the next one follows quickly. A document is given up when it has failed the most tries or has
 * waited the longest age; the give-up is logged as an error and counted.
 * <p>
 * The store itself is the caller's: a document is written under its stable id and the store overwrites a row of the
 * same id, so storing a document that was already stored leaves one row.
 */
@Slf4j
public final class FailedDocumentRetrier {

    /**
     * Runs a task once after a delay on a thread of its own; the retry schedules its next try after each one. It must
     * run the tasks one at a time, never two together.
     */
    public interface Scheduler {

        void schedule(Runnable task, Duration delay);

        /** Ends the scheduler and drops the task that waits. */
        void shutdown();
    }

    /** The pause between the batches of a queue that is being drained. */
    private static final Duration DRAIN_PAUSE = Duration.ofMillis(250);
    /** How many ids a log line names. */
    private static final int LOGGED_IDS = 10;

    private final FailedDocumentSink sink;
    private final Clock clock;
    private final Scheduler scheduler;
    private final Consumer<List<Document>> writer;
    private final Consumer<List<String>> purger;
    private final int largestBatch;
    private final int maxAttempts;
    private final Duration maxAge;
    private final Duration initialDelay;
    private final Duration maxDelay;

    /** Told which documents a retry stored (QF-8b); called after the retry's counts are kept. */
    private final List<Consumer<List<Document>>> storedListeners = new CopyOnWriteArrayList<>();
    private final AtomicLong failed = new AtomicLong();
    private final AtomicLong deferred = new AtomicLong();
    private final AtomicLong retried = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicBoolean scheduled = new AtomicBoolean();
    private volatile boolean shutDown;
    private volatile int batchSize;
    private volatile int consecutiveFailures;
    private volatile Duration nextDelay;

    /**
     * @param writer the store of a batch; it throws when the store fails
     * @param purger deletes documents by id from the store; used for a document that was removed while its retry was
     *               storing it, so that the store does not keep what was deleted
     */
    public FailedDocumentRetrier(VectorStoreRetryProperties properties, FailedDocumentSink sink, Clock clock,
                                 Scheduler scheduler, Consumer<List<Document>> writer, Consumer<List<String>> purger) {
        this.sink = sink;
        this.clock = clock;
        this.scheduler = scheduler;
        this.writer = writer;
        this.purger = purger;
        this.largestBatch = Math.max(1, properties.getBatchSize());
        this.maxAttempts = Math.max(1, properties.getMaxAttempts());
        this.maxAge = properties.getMaxAge() != null ? properties.getMaxAge() : Duration.ofHours(1);
        Duration initial = properties.getInitialDelay() != null ? properties.getInitialDelay() : Duration.ofSeconds(10);
        this.initialDelay = initial.toMillis() < 1 ? Duration.ofMillis(1) : initial;
        Duration longest = properties.getMaxDelay() != null ? properties.getMaxDelay() : Duration.ofMinutes(5);
        this.maxDelay = longest.compareTo(this.initialDelay) < 0 ? this.initialDelay : longest;
        this.batchSize = this.largestBatch;
        this.nextDelay = this.initialDelay;
    }

    /** A scheduler on one daemon thread, which exists only once a retry has been scheduled. */
    public static Scheduler threadScheduler() {
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "contexa-vector-store-retry");
            thread.setDaemon(true);
            return thread;
        });
        executor.setRemoveOnCancelPolicy(true);
        executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        return new Scheduler() {
            @Override
            public void schedule(Runnable task, Duration delay) {
                executor.schedule(task, delay.toMillis(), TimeUnit.MILLISECONDS);
            }

            @Override
            public void shutdown() {
                executor.shutdownNow();
            }
        };
    }

    /**
     * Registers a listener of the documents a retry stored (QF-8b). It is told after the store has them and the retry's
     * counts are kept, with the documents that stay stored: a document removed while its store ran is deleted again and
     * is not told. A listener that throws is logged and changes nothing of the retry.
     */
    public void addStoredListener(Consumer<List<Document>> listener) {
        if (listener != null) {
            storedListeners.add(listener);
        }
    }

    /** Takes in documents whose store failed and makes sure a retry is scheduled. */
    public void enqueue(List<Document> documents) {
        if (documents.isEmpty()) {
            return;
        }
        takeIn(documents, failed);
        log.warn("[FailedDocumentRetrier] {} documents wait for a vector store retry", documents.size());
    }

    /**
     * QF-25 (b): takes in documents that were not tried, because their writer had no room to store them now, and makes
     * sure a retry is scheduled. They wait and are stored exactly as failed documents are, and are counted as deferred.
     */
    public void defer(List<Document> documents) {
        if (documents.isEmpty()) {
            return;
        }
        takeIn(documents, deferred);
        log.warn("[FailedDocumentRetrier] {} documents were left to the vector store retry because the learning "
                + "executor had no room for their store", documents.size());
    }

    private void takeIn(List<Document> documents, AtomicLong counter) {
        Instant now = clock.instant();
        List<FailedDocument> entries = new ArrayList<>(documents.size());
        for (Document document : documents) {
            entries.add(new FailedDocument(document, now, 0));
        }
        List<FailedDocument> pushedOut = sink.add(entries);
        counter.addAndGet(entries.size());
        if (!pushedOut.isEmpty()) {
            dropped.addAndGet(pushedOut.size());
            log.error("[FailedDocumentRetrier] The retry queue is full, the {} oldest waiting documents were dropped "
                    + "and their records are lost: ids={}", pushedOut.size(), ids(pushedOut));
        }
        scheduleNext(consecutiveFailures == 0 ? initialDelay : delayAfter(consecutiveFailures));
    }

    /**
     * Drops the waiting documents the condition accepts, on purpose (a document deleted by id, a purged user's). They
     * are not counted as dropped; a document of them whose store is running now is deleted again when it ends.
     *
     * @return how many documents were dropped
     */
    public int discard(Predicate<Document> condition) {
        List<FailedDocument> removed = sink.removeWhere(entry -> condition.test(entry.document()));
        if (!removed.isEmpty()) {
            log.info("[FailedDocumentRetrier] {} waiting documents were removed from the retry queue on purpose: ids={}",
                    removed.size(), ids(removed));
        }
        return removed.size();
    }

    public StoreFailureStats stats() {
        return new StoreFailureStats(failed.get(), sink.size(), retried.get(), dropped.get(), deferred.get());
    }

    /** Stops the retry; the documents that still wait are not stored (the default queue is in memory). */
    public void shutdown() {
        shutDown = true;
        scheduler.shutdown();
        int waiting;
        try {
            waiting = sink.size();
        } catch (RuntimeException unreadable) {
            return;
        }
        if (waiting > 0) {
            log.warn("[FailedDocumentRetrier] The retry stops with {} documents still waiting; they are not stored "
                    + "unless the queue outlives the process", waiting);
        }
    }

    private void scheduleNext(Duration delay) {
        if (shutDown || !scheduled.compareAndSet(false, true)) {
            return;
        }
        try {
            scheduler.schedule(this::tick, delay);
        } catch (RuntimeException rejected) {
            scheduled.set(false);
            log.warn("[FailedDocumentRetrier] The retry could not be scheduled: {}", rejected.getMessage());
        }
    }

    /** The scheduled task: one cycle, then the next one while documents wait. */
    private void tick() {
        scheduled.set(false);
        if (shutDown) {
            return;
        }
        try {
            runCycle();
        } catch (RuntimeException unexpected) {
            log.error("[FailedDocumentRetrier] A retry cycle failed unexpectedly", unexpected);
            registerFailedCycle();
        }
        boolean waiting;
        try {
            waiting = sink.size() > 0;
        } catch (RuntimeException unreadable) {
            waiting = true;
        }
        if (waiting) {
            scheduleNext(nextDelay);
        } else {
            resetBackoff();
        }
    }

    /** One try: gives up the documents that waited too long, then stores the oldest batch. */
    void runCycle() {
        Instant oldestAllowed = clock.instant().minus(maxAge);
        giveUp(sink.removeWhere(entry -> !entry.firstFailedAt().isAfter(oldestAllowed)),
                "waited longer than " + maxAge);

        List<FailedDocument> batch = sink.oldest(batchSize);
        if (batch.isEmpty()) {
            resetBackoff();
            return;
        }
        List<Document> documents = new ArrayList<>(batch.size());
        for (FailedDocument entry : batch) {
            documents.add(entry.document());
        }
        try {
            writer.accept(documents);
        } catch (RuntimeException failure) {
            retryFailed(batch, failure);
            return;
        }
        retryStored(batch);
    }

    private void retryStored(List<FailedDocument> batch) {
        Set<FailedDocument> sent = new HashSet<>(batch);
        List<FailedDocument> removed = sink.removeWhere(sent::contains);
        retried.addAndGet(removed.size());
        if (removed.size() < batch.size()) {
            // Removed while the store wrote it (deleted by id, user purged): the row it wrote must not stay.
            Set<FailedDocument> found = new HashSet<>(removed);
            List<String> missing = new ArrayList<>();
            for (FailedDocument entry : batch) {
                if (!found.contains(entry)) {
                    missing.add(entry.id());
                }
            }
            deleteAgain(missing);
        }
        log.info("[FailedDocumentRetrier] {} documents were stored by a retry", removed.size());
        consecutiveFailures = 0;
        batchSize = Math.min(largestBatch, batchSize * 2);
        nextDelay = DRAIN_PAUSE;
        tellStored(removed);
    }

    /** Tells the listeners which documents the retry stored; a listener's failure is logged and goes no further. */
    private void tellStored(List<FailedDocument> removed) {
        if (removed.isEmpty() || storedListeners.isEmpty()) {
            return;
        }
        List<Document> documents = new ArrayList<>(removed.size());
        for (FailedDocument entry : removed) {
            documents.add(entry.document());
        }
        List<Document> told = List.copyOf(documents);
        for (Consumer<List<Document>> listener : storedListeners) {
            try {
                listener.accept(told);
            } catch (RuntimeException failure) {
                log.warn("[FailedDocumentRetrier] A listener of the stored documents failed: ids={}: {}",
                        ids(removed), failure.getMessage());
                log.debug("[FailedDocumentRetrier] Listener failure", failure);
            }
        }
    }

    private void retryFailed(List<FailedDocument> batch, RuntimeException failure) {
        registerFailedCycle();
        List<FailedDocument> again = new ArrayList<>(batch.size());
        Set<FailedDocument> exhausted = new HashSet<>();
        for (FailedDocument entry : batch) {
            FailedDocument next = entry.afterFailedAttempt();
            if (next.attempts() >= maxAttempts) {
                exhausted.add(entry);
            } else {
                again.add(next);
            }
        }
        sink.requeue(again);
        if (!exhausted.isEmpty()) {
            giveUp(sink.removeWhere(exhausted::contains), "failed " + maxAttempts + " tries");
        }
        log.warn("[FailedDocumentRetrier] Storing {} waiting documents failed again (failed cycles in a row={}, "
                        + "next try in {}): {}", batch.size(), consecutiveFailures, nextDelay, failure.getMessage());
        log.debug("[FailedDocumentRetrier] Retry failure", failure);
    }

    /** A cycle failed: the next wait doubles and the next batch is half the size. */
    private void registerFailedCycle() {
        consecutiveFailures++;
        batchSize = Math.max(1, batchSize / 2);
        nextDelay = delayAfter(consecutiveFailures);
    }

    private void resetBackoff() {
        consecutiveFailures = 0;
        batchSize = largestBatch;
        nextDelay = initialDelay;
    }

    /** The wait after the given number of failed cycles in a row: the initial delay doubled each time, up to the longest. */
    private Duration delayAfter(int failedCycles) {
        long delayMs = initialDelay.toMillis();
        long longestMs = maxDelay.toMillis();
        for (int i = 0; i < failedCycles && delayMs < longestMs; i++) {
            delayMs *= 2;
        }
        return Duration.ofMillis(Math.min(delayMs, longestMs));
    }

    private void giveUp(List<FailedDocument> givenUp, String reason) {
        if (givenUp.isEmpty()) {
            return;
        }
        dropped.addAndGet(givenUp.size());
        log.error("[FailedDocumentRetrier] Gave up storing {} documents ({}); their records are lost: ids={}",
                givenUp.size(), reason, ids(givenUp));
    }

    private void deleteAgain(List<String> documentIds) {
        try {
            purger.accept(documentIds);
        } catch (RuntimeException failure) {
            log.error("[FailedDocumentRetrier] Documents removed while their store ran could not be deleted again: ids={}",
                    documentIds, failure);
        }
    }

    private static List<String> ids(List<FailedDocument> entries) {
        List<String> ids = new ArrayList<>(Math.min(entries.size(), LOGGED_IDS));
        for (FailedDocument entry : entries) {
            if (ids.size() >= LOGGED_IDS) {
                break;
            }
            ids.add(entry.id());
        }
        return ids;
    }
}
