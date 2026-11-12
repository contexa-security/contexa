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
import org.springframework.context.event.EventListener;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Async;

import java.time.Instant;
import java.util.Map;
import java.util.TreeMap;

/**
 * Async event listener that persists AuditRecord to database.
 * Decouples audit recording from business logic execution.
 *
 * <p>PR-200: a database that does not answer takes no record, and every record of the outage used to end in an error
 * with its stack, tens of thousands of them a minute in the application's log. While the database is known to be down
 * nothing is asked of it; the records it did not take are counted, told once and then a line a minute, and one record
 * of how many there were, of which kinds and between which times is written when it answers again.
 */
@Slf4j
public class AuditPersistenceListener {

    private final CentralAuditFacade centralAuditFacade;
    @Nullable
    private final StoreGate database;
    private final RepeatedFailure unwrittenReports = new RepeatedFailure();
    private final Object ledger = new Object();
    private final Map<String, Long> unwrittenByCategory = new TreeMap<>();
    private long unwritten;
    private Instant unwrittenFrom;
    private volatile boolean owed;

    public AuditPersistenceListener(CentralAuditFacade centralAuditFacade) {
        this(centralAuditFacade, null);
    }

    public AuditPersistenceListener(CentralAuditFacade centralAuditFacade, @Nullable StoreGate database) {
        this.centralAuditFacade = centralAuditFacade;
        this.database = database;
        if (database != null) {
            database.whenBack(this::recordUnwritten);
        }
    }

    @Async("contexaTaskExecutor")
    @EventListener
    public void onAuditRecordEvent(AuditRecordEvent event) {
        AuditRecord record = event.getAuditRecord();
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

    private void unwritten(AuditRecord record, @Nullable Exception failure) {
        String category = record.getEventCategory() != null ? record.getEventCategory().name() : "UNKNOWN";
        synchronized (ledger) {
            if (unwritten == 0) {
                unwrittenFrom = Instant.now();
            }
            unwritten++;
            unwrittenByCategory.merge(category, 1L, Long::sum);
            owed = true;
        }
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
        Instant from;
        Map<String, Long> byCategory;
        synchronized (ledger) {
            owed = false;
            if (unwritten == 0) {
                return;
            }
            records = unwritten;
            from = unwrittenFrom;
            byCategory = new TreeMap<>(unwrittenByCategory);
            unwritten = 0;
            unwrittenFrom = null;
            unwrittenByCategory.clear();
        }
        Instant to = Instant.now();
        try {
            centralAuditFacade.persist(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.SECURITY_ERROR)
                    .principalName("SYSTEM")
                    .eventSource("CORE")
                    .resourceIdentifier("AuditLog")
                    .resourceUri("/errors/AuditLog")
                    .action("AUDIT_RECORDS_NOT_WRITTEN")
                    .decision("NOT_RECORDED")
                    .outcome("STORE_UNAVAILABLE")
                    .reason(records + " audit records between " + from + " and " + to
                            + " were not written: Contexa's database did not answer.")
                    .details(Map.of("from", from.toString(), "to", to.toString(), "records", records,
                            "byCategory", byCategory))
                    .build());
        } catch (Exception failure) {
            log.error("[Contexa] {} audit records between {} and {} were not written ({}), and the audit log did not "
                    + "take the record of it.", records, from, to, byCategory, failure);
        }
    }
}
