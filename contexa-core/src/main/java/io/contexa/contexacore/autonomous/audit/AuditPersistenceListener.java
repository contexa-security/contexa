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
package io.contexa.contexacore.autonomous.audit;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.store.RepeatedFailure;
import io.contexa.contexacommon.store.StoreFailures;
import io.contexa.contexacommon.store.StoreGate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.context.event.EventListener;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Event listener that persists AuditRecord to database, off the thread that made the record.
 * Decouples audit recording from business logic execution.
 *
 * <p>PR-188: the records are written by a few threads of the listener's own, behind a line of a fixed length. They used
 * to go through the shared executor, which hands the work back to the thread that asks when it is full, and under load
 * the application's request threads wrote audit records to Contexa's database themselves. A record that finds the line
 * full is not written: it is counted with the others that were not, told once and then a line a minute, and stands in
 * the record of how many there were, which is written at most once a minute while the line stays full.
 *
 * <p>PR-200: a database that does not answer takes no record, and every record of the outage used to end in an error
 * with its stack, tens of thousands of them a minute in the application's log. While the database is known to be down
 * nothing is asked of it; the records it did not take are counted, told once and then a line a minute, and one record
 * of how many there were, of which kinds and between which times is written when it answers again.
 */
@Slf4j
public class AuditPersistenceListener implements DisposableBean {

    private static final int WRITERS = 4;
    private static final int WAITING = 2_000;
    private static final long IDLE_SECONDS = 60L;
    private static final long STOP_WAIT_SECONDS = 10L;
    private static final long LINE_FULL_RECORD_EVERY_NANOS = TimeUnit.MINUTES.toNanos(1);

    private final CentralAuditFacade centralAuditFacade;
    @Nullable
    private final StoreGate database;
    private final Executor writers;
    @Nullable
    private final ThreadPoolExecutor ownWriters;
    private final RepeatedFailure unwrittenReports = new RepeatedFailure();
    private final RepeatedFailure lineFullReports = new RepeatedFailure();
    private final Object ledger = new Object();
    private final Map<String, Long> unwrittenByCategory = new TreeMap<>();
    private long unwritten;
    private long unwrittenLineFull;
    private Instant unwrittenFrom;
    private boolean lineFullRecorded;
    private long lineFullRecordedAtNanos;
    private volatile boolean owed;

    public AuditPersistenceListener(CentralAuditFacade centralAuditFacade) {
        this(centralAuditFacade, null);
    }

    public AuditPersistenceListener(CentralAuditFacade centralAuditFacade, @Nullable StoreGate database) {
        this(centralAuditFacade, database, null);
    }

    /**
     * @param writers what writes the records; null for the listener's own threads
     */
    AuditPersistenceListener(CentralAuditFacade centralAuditFacade, @Nullable StoreGate database,
                             @Nullable Executor writers) {
        this.centralAuditFacade = centralAuditFacade;
        this.database = database;
        this.ownWriters = writers == null ? newWriters() : null;
        this.writers = writers != null ? writers : this.ownWriters;
        if (database != null) {
            database.whenBack(this::recordUnwritten);
        }
    }

    private static ThreadPoolExecutor newWriters() {
        AtomicInteger names = new AtomicInteger();
        ThreadPoolExecutor executor = new ThreadPoolExecutor(WRITERS, WRITERS, IDLE_SECONDS, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(WAITING), work -> {
            Thread thread = new Thread(work, "contexa-audit-write-" + names.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }, new ThreadPoolExecutor.AbortPolicy());
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }

    @EventListener
    public void onAuditRecordEvent(AuditRecordEvent event) {
        AuditRecord record = event.getAuditRecord();
        if (database != null && database.isDown()) {
            unwritten(record, null);
            return;
        }
        try {
            writers.execute(() -> write(record));
        } catch (RejectedExecutionException fullOrStopped) {
            lineFull(record);
        }
    }

    private void write(AuditRecord record) {
        // the database can have gone down while the record waited
        if (database != null && database.isDown()) {
            unwritten(record, null);
            return;
        }
        try {
            centralAuditFacade.persist(record);
        } catch (Exception e) {
            if (StoreFailures.isStoreFailure(e)) {
                unwritten(record, e);
                return;
            }
            log.error("Failed to persist audit record asynchronously: category={}, principal={}",
                    record.getEventCategory(), record.getPrincipalName(), e);
            return;
        }
        if (owed) {
            recordUnwritten();
        }
    }

    private void count(AuditRecord record, boolean lineFull) {
        String category = record.getEventCategory() != null ? record.getEventCategory().name() : "UNKNOWN";
        synchronized (ledger) {
            if (unwritten == 0) {
                unwrittenFrom = Instant.now();
            }
            unwritten++;
            if (lineFull) {
                unwrittenLineFull++;
            }
            unwrittenByCategory.merge(category, 1L, Long::sum);
            owed = true;
        }
    }

    /** A record more than the line holds, or made after it stopped: counted, and the thread that made it does not write it. */
    private void lineFull(AuditRecord record) {
        count(record, true);
        long unreported = lineFullReports.count();
        if (unreported > 0) {
            log.error("[Contexa] {} audit records were not written since this was last said: more were made than Contexa "
                    + "writes, and the line of those waiting was full or stopped. How many there were, of which kinds, is "
                    + "written to the audit log.", unreported);
        }
    }

    private void unwritten(AuditRecord record, @Nullable Exception failure) {
        count(record, false);
        long unreported = unwrittenReports.count();
        if (unreported > 0) {
            log.error("[Contexa] {} audit records were not written since this was last said: Contexa's database does not "
                    + "answer ({}). How many there were, of which kinds, is written to the audit log when it answers again.",
                    unreported, failure != null ? describe(failure) : "known to be down, not asked");
        }
    }

    private static String describe(Exception failure) {
        Throwable root = NestedExceptionUtils.getMostSpecificCause(failure);
        return root.getClass().getSimpleName() + ": " + root.getMessage();
    }

    /** Leaves one record of the records that were not written; run when the database answers again. */
    private void recordUnwritten() {
        if (database != null && database.isDown()) {
            return;
        }
        long records;
        long lineFull;
        Instant from;
        Map<String, Long> byCategory;
        synchronized (ledger) {
            if (unwritten == 0) {
                owed = false;
                return;
            }
            // a line that stays full is written on all the while: the record of it is left once a minute, not after
            // every record that was written
            if (unwrittenLineFull > 0 && lineFullRecorded
                    && System.nanoTime() - lineFullRecordedAtNanos < LINE_FULL_RECORD_EVERY_NANOS) {
                return;
            }
            owed = false;
            records = unwritten;
            lineFull = unwrittenLineFull;
            from = unwrittenFrom;
            byCategory = new TreeMap<>(unwrittenByCategory);
            unwritten = 0;
            unwrittenLineFull = 0;
            unwrittenFrom = null;
            unwrittenByCategory.clear();
            if (lineFull > 0) {
                lineFullRecorded = true;
                lineFullRecordedAtNanos = System.nanoTime();
            }
        }
        Instant to = Instant.now();
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("from", from.toString());
        details.put("to", to.toString());
        details.put("records", records);
        details.put("byCategory", byCategory);
        if (lineFull > 0) {
            details.put("lineFull", lineFull);
        }
        try {
            centralAuditFacade.persist(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.SECURITY_ERROR)
                    .principalName("SYSTEM")
                    .eventSource("CORE")
                    .resourceIdentifier("AuditLog")
                    .resourceUri("/errors/AuditLog")
                    .action("AUDIT_RECORDS_NOT_WRITTEN")
                    .decision("NOT_RECORDED")
                    .outcome(lineFull == records ? "AUDIT_LINE_FULL" : "STORE_UNAVAILABLE")
                    .reason(records + " audit records between " + from + " and " + to
                            + " were not written: " + why(records, lineFull))
                    .details(details)
                    .build());
        } catch (Exception failure) {
            log.error("[Contexa] {} audit records between {} and {} were not written ({}), and the audit log did not "
                    + "take the record of it.", records, from, to, byCategory, failure);
        }
    }

    private static String why(long records, long lineFull) {
        if (lineFull == 0) {
            return "Contexa's database did not answer.";
        }
        if (lineFull == records) {
            return "more were made than Contexa writes, and the line of those waiting was full.";
        }
        return "Contexa's database did not answer, and for " + lineFull + " of them the line of those waiting was full.";
    }

    @Override
    public void destroy() {
        if (ownWriters == null) {
            return;
        }
        ownWriters.shutdown();
        try {
            if (!ownWriters.awaitTermination(STOP_WAIT_SECONDS, TimeUnit.SECONDS)) {
                log.error("[Contexa] Audit records were still being written when the listener was stopped; {} were "
                        + "waiting and are not written", ownWriters.getQueue().size());
                ownWriters.shutdownNow();
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            ownWriters.shutdownNow();
        }
    }
}
