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
package io.contexa.contexaiam.security.xacml.pap.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionSynchronizationUtils;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * D61: a reload inside the transaction that changed the policies held the reload lock while the transaction flushed
 * its writes, so two administrators who changed and deleted the same policy waited for each other until a restart. The
 * reload runs once the transaction has committed.
 */
class PolicyReloadAfterCommitTest {

    @AfterEach
    void endTheTransaction() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
        TransactionSynchronizationManager.setActualTransactionActive(false);
    }

    @Test
    @DisplayName("with no transaction the reload runs at once")
    void withoutATransactionTheReloadRunsAtOnce() {
        AtomicInteger reloads = new AtomicInteger();

        PolicyReloadAfterCommit.schedule(reloads::incrementAndGet);

        assertThat(reloads).hasValue(1);
    }

    @Test
    @DisplayName("in a transaction the reload waits for the commit, and runs once however many changes asked for it")
    void inATransactionTheReloadWaitsForTheCommit() {
        AtomicInteger reloads = new AtomicInteger();
        beginTransaction();

        PolicyReloadAfterCommit.schedule(reloads::incrementAndGet);
        PolicyReloadAfterCommit.schedule(reloads::incrementAndGet);

        assertThat(reloads).hasValue(0);
        List<TransactionSynchronization> registered = TransactionSynchronizationManager.getSynchronizations();
        TransactionSynchronizationUtils.invokeAfterCommit(registered);
        assertThat(reloads).hasValue(1);
    }

    @Test
    @DisplayName("a rolled-back transaction reloads nothing")
    void aRollbackReloadsNothing() {
        AtomicInteger reloads = new AtomicInteger();
        beginTransaction();

        PolicyReloadAfterCommit.schedule(reloads::incrementAndGet);
        TransactionSynchronizationUtils.invokeAfterCompletion(TransactionSynchronizationManager.getSynchronizations(),
                TransactionSynchronization.STATUS_ROLLED_BACK);

        assertThat(reloads).hasValue(0);
    }

    @Test
    @DisplayName("a reload that fails after the commit is logged, the committed change stands")
    void aFailedReloadDoesNotFailTheCommit() {
        beginTransaction();
        PolicyReloadAfterCommit.schedule(() -> {
            throw new IllegalStateException("the policies cannot be read");
        });

        assertThatCode(() -> TransactionSynchronizationUtils.invokeAfterCommit(
                TransactionSynchronizationManager.getSynchronizations())).doesNotThrowAnyException();
    }

    private static void beginTransaction() {
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
    }
}
