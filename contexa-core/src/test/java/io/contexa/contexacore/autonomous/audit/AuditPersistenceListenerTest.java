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
import io.contexa.contexacommon.store.ContexaStores;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * PR-200: the records a silent database does not take are counted and told once, not one error with its stack for each,
 * and how many there were is on the audit log once the database answers again.
 *
 * <p>PR-188: the record is written by the listener's own threads, and one the line has no place for is counted with the
 * others, not written by the thread that made it.
 */
@ExtendWith(OutputCaptureExtension.class)
class AuditPersistenceListenerTest {

    private static final String TOLD = "audit records were not written since this was last said";
    private static final String EACH = "Failed to persist audit record asynchronously";

    private final ContexaStores stores = new ContexaStores();
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final AtomicBoolean answering = new AtomicBoolean();
    private final List<AuditRecord> written = new CopyOnWriteArrayList<>();

    @AfterEach
    void stop() {
        stores.destroy();
    }

    private void aDatabaseThatAnswersOnlyWhenTold() {
        doAnswer(asked -> {
            if (!answering.get()) {
                throw new QueryTimeoutException("no answer");
            }
            written.add(asked.getArgument(0));
            return null;
        }).when(audit).persist(any());
    }

    private void gateDown() {
        stores.database().watchWith(() -> {
            if (!answering.get()) {
                throw new IllegalStateException("still down");
            }
        });
        stores.database().fail(new QueryTimeoutException("no answer"));
        assertThat(stores.database().isDown()).isTrue();
    }

    private AuditRecordEvent event(AuditEventCategory category) {
        return new AuditRecordEvent(this, AuditRecord.builder().eventCategory(category).principalName("alice").build());
    }

    @Test
    @DisplayName("while the database is known to be down nothing is asked of it and the outage is told once")
    void aDatabaseKnownToBeDownIsNotAsked(CapturedOutput output) {
        gateDown();
        AuditPersistenceListener listener = new AuditPersistenceListener(audit, stores.database(), Runnable::run);

        for (int record = 0; record < 300; record++) {
            listener.onAuditRecordEvent(event(AuditEventCategory.AUTHENTICATION_SUCCESS));
        }

        verify(audit, never()).persist(any());
        assertThat(StringUtils.countOccurrencesOf(output.getAll(), TOLD)).isEqualTo(1);
        assertThat(output.getAll()).doesNotContain(EACH);
    }

    @Test
    @DisplayName("records a silent database refuses are told once, by cause and without a stack for each")
    void recordsASilentDatabaseRefusesAreToldOnce(CapturedOutput output) {
        aDatabaseThatAnswersOnlyWhenTold();
        AuditPersistenceListener listener = new AuditPersistenceListener(audit, null, Runnable::run);

        for (int record = 0; record < 300; record++) {
            listener.onAuditRecordEvent(event(AuditEventCategory.AUTHENTICATION_SUCCESS));
        }

        verify(audit, times(300)).persist(any());
        assertThat(StringUtils.countOccurrencesOf(output.getAll(), TOLD)).isEqualTo(1);
        assertThat(output.getAll()).contains("QueryTimeoutException: no answer").doesNotContain(EACH)
                .doesNotContain("at io.contexa.contexacore.autonomous.audit.AuditPersistenceListener");
    }

    @Test
    @DisplayName("the audit log holds how many records were not written, of which kinds, once the database answers again")
    void theAuditLogHoldsHowManyWereNotWritten() {
        aDatabaseThatAnswersOnlyWhenTold();
        gateDown();
        AuditPersistenceListener listener = new AuditPersistenceListener(audit, stores.database(), Runnable::run);
        listener.onAuditRecordEvent(event(AuditEventCategory.AUTHENTICATION_SUCCESS));
        listener.onAuditRecordEvent(event(AuditEventCategory.AUTHENTICATION_SUCCESS));
        listener.onAuditRecordEvent(event(AuditEventCategory.SECURITY_DECISION));
        listener.onAuditRecordEvent(new AuditRecordEvent(this, AuditRecord.builder().principalName("alice").build()));

        answering.set(true);
        await().atMost(Duration.ofSeconds(5)).until(() -> !written.isEmpty());

        assertThat(written).hasSize(1);
        AuditRecord record = written.get(0);
        assertThat(record.getEventCategory()).isEqualTo(AuditEventCategory.SECURITY_ERROR);
        assertThat(record.getAction()).isEqualTo("AUDIT_RECORDS_NOT_WRITTEN");
        assertThat(record.getOutcome()).isEqualTo("STORE_UNAVAILABLE");
        assertThat(record.getReason()).startsWith("4 audit records between ");
        assertThat(record.getDetails()).containsEntry("records", 4L).containsEntry("byCategory",
                Map.of("AUTHENTICATION_SUCCESS", 2L, "SECURITY_DECISION", 1L, "UNKNOWN", 1L));

        listener.onAuditRecordEvent(event(AuditEventCategory.AUTHENTICATION_SUCCESS));

        assertThat(written).as("the count is written once; the next record is an ordinary one").hasSize(2);
        assertThat(written.get(1).getEventCategory()).isEqualTo(AuditEventCategory.AUTHENTICATION_SUCCESS);
    }

    @Test
    @DisplayName("without a gate the count is written after the first record the database takes again")
    void withoutAGateTheCountFollowsTheFirstRecordWritten() {
        aDatabaseThatAnswersOnlyWhenTold();
        AuditPersistenceListener listener = new AuditPersistenceListener(audit, null, Runnable::run);
        for (int record = 0; record < 7; record++) {
            listener.onAuditRecordEvent(event(AuditEventCategory.AUTHENTICATION_SUCCESS));
        }

        answering.set(true);
        listener.onAuditRecordEvent(event(AuditEventCategory.SECURITY_DECISION));

        assertThat(written).hasSize(2);
        assertThat(written.get(0).getEventCategory()).isEqualTo(AuditEventCategory.SECURITY_DECISION);
        assertThat(written.get(1).getAction()).isEqualTo("AUDIT_RECORDS_NOT_WRITTEN");
        assertThat(written.get(1).getDetails()).containsEntry("records", 7L);
    }

    @Test
    @DisplayName("the record is written by the listener's own thread, not by the thread that made it")
    void theRecordIsWrittenOffTheThreadThatMadeIt() {
        List<String> threads = new CopyOnWriteArrayList<>();
        doAnswer(asked -> {
            threads.add(Thread.currentThread().getName());
            return null;
        }).when(audit).persist(any());
        AuditPersistenceListener listener = new AuditPersistenceListener(audit);
        try {
            listener.onAuditRecordEvent(event(AuditEventCategory.AUTHENTICATION_SUCCESS));

            await().atMost(Duration.ofSeconds(5)).until(() -> !threads.isEmpty());
            assertThat(threads).allMatch(name -> name.startsWith("contexa-audit-write-"));
        } finally {
            listener.destroy();
        }
    }

    @Test
    @DisplayName("a record the line has no place for is counted, told once, and stands on the audit log; its thread does not write it")
    void aRecordTheLineHasNoPlaceForIsCountedNotWritten(CapturedOutput output) {
        answering.set(true);
        aDatabaseThatAnswersOnlyWhenTold();
        AtomicBoolean full = new AtomicBoolean(true);
        AuditPersistenceListener listener = new AuditPersistenceListener(audit, null, work -> {
            if (full.get()) {
                throw new RejectedExecutionException("full");
            }
            work.run();
        });

        for (int record = 0; record < 5; record++) {
            listener.onAuditRecordEvent(event(AuditEventCategory.AUTHENTICATION_SUCCESS));
        }

        verify(audit, never()).persist(any());
        assertThat(StringUtils.countOccurrencesOf(output.getAll(), TOLD)).isEqualTo(1);
        assertThat(output.getAll()).contains("the line of those waiting was full").doesNotContain(EACH);

        full.set(false);
        listener.onAuditRecordEvent(event(AuditEventCategory.SECURITY_DECISION));

        assertThat(written).hasSize(2);
        assertThat(written.get(0).getEventCategory()).isEqualTo(AuditEventCategory.SECURITY_DECISION);
        assertThat(written.get(1).getAction()).isEqualTo("AUDIT_RECORDS_NOT_WRITTEN");
        assertThat(written.get(1).getOutcome()).isEqualTo("AUDIT_LINE_FULL");
        assertThat(written.get(1).getDetails()).containsEntry("records", 5L).containsEntry("lineFull", 5L);
    }

    @Test
    @DisplayName("a record that fails for another reason is still told each time, with its stack, and is not counted")
    void aRecordThatFailsForAnotherReasonIsStillTold(CapturedOutput output) {
        doThrow(new IllegalStateException("bad record")).when(audit).persist(any());
        AuditPersistenceListener listener = new AuditPersistenceListener(audit, stores.database(), Runnable::run);

        for (int record = 0; record < 3; record++) {
            listener.onAuditRecordEvent(event(AuditEventCategory.AUTHENTICATION_SUCCESS));
        }

        assertThat(StringUtils.countOccurrencesOf(output.getAll(), EACH)).isEqualTo(3);
        assertThat(output.getAll()).contains("IllegalStateException: bad record").doesNotContain(TOLD);
    }
}
