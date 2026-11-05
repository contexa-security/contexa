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
package io.contexa.contexacommon.store;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.dao.QueryTimeoutException;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/** Q-7: the calls that went on without a decision stay on record, whichever store was away. */
@ExtendWith(OutputCaptureExtension.class)
class ContexaStoresTest {

    private final ContexaStores stores = new ContexaStores();
    private final List<ContexaStores.UndecidedCalls> records = new CopyOnWriteArrayList<>();

    @AfterEach
    void stop() {
        stores.destroy();
    }

    private static void watchAnswering(StoreGate gate, AtomicBoolean answering) {
        gate.watchWith(() -> {
            if (!answering.get()) {
                throw new IllegalStateException("still down");
            }
        });
    }

    @Test
    @DisplayName("while the database is away the count waits: only it could take the record")
    void theCountWaitsForTheDatabase(CapturedOutput output) {
        stores.setRecorder(records::add);
        AtomicBoolean answering = new AtomicBoolean();
        watchAnswering(stores.database(), answering);
        stores.database().fail(new QueryTimeoutException("no answer"));

        stores.passedWithoutDecision();
        stores.passedWithoutDecision();
        stores.passedWithoutDecision();

        assertThat(records).isEmpty();
        assertThat(output).as("the log has it from the start").contains("protected calls went on without a decision");

        answering.set(true);
        await().atMost(Duration.ofSeconds(5)).until(() -> !records.isEmpty());
        assertThat(records).hasSize(1);
        assertThat(records.get(0).calls()).isEqualTo(3);
        assertThat(records.get(0).from()).isBeforeOrEqualTo(records.get(0).to());
    }

    @Test
    @DisplayName("while only Redis is away the database takes the record at once")
    void theDatabaseTakesTheRecordOfARedisOutage() {
        stores.setRecorder(records::add);
        watchAnswering(stores.redis(), new AtomicBoolean());
        stores.redis().fail(new QueryTimeoutException("no answer"));

        stores.passedWithoutDecision();

        assertThat(records).hasSize(1);
        assertThat(records.get(0).calls()).isEqualTo(1);
    }

    @Test
    @DisplayName("the calls after the first are recorded when the store comes back")
    void theRestIsRecordedWhenTheStoreComesBack() {
        stores.setRecorder(records::add);
        AtomicBoolean answering = new AtomicBoolean();
        watchAnswering(stores.redis(), answering);
        stores.redis().fail(new QueryTimeoutException("no answer"));
        stores.passedWithoutDecision();
        stores.passedWithoutDecision();
        stores.passedWithoutDecision();

        answering.set(true);
        await().atMost(Duration.ofSeconds(5)).until(() -> records.size() == 2);

        assertThat(records.stream().mapToLong(ContexaStores.UndecidedCalls::calls).sum()).isEqualTo(3);
    }

    @Test
    @DisplayName("a record the audit log does not take is still in the log, with its numbers")
    void aRecordTheAuditLogDoesNotTake(CapturedOutput output) {
        stores.setRecorder(record -> {
            throw new IllegalStateException("the audit log is read only");
        });

        stores.passedWithoutDecision();

        assertThat(output).contains("1 protected calls").contains("did not take the record");
    }

    @Test
    @DisplayName("a store that is up keeps nothing back: without a recorder nothing fails either")
    void nothingIsDownByDefault() {
        assertThat(stores.anyDown()).isFalse();
        stores.passedWithoutDecision();
    }

    @Test
    @DisplayName("either store down is an outage")
    void eitherStoreDown() {
        watchAnswering(stores.redis(), new AtomicBoolean());

        stores.redis().fail(new QueryTimeoutException("no answer"));

        assertThat(stores.anyDown()).isTrue();
    }
}
