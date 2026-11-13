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

import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Reloads the authorization policies once the transaction that changed them has committed (D61). The reload is
 * serialized and reads the policies; run inside the changing transaction, it flushed that transaction's pending writes
 * while holding the reload lock, so a transaction that held a row lock and waited for the reload lock, and one that held
 * the reload lock and waited for the row lock, waited for each other until the server was restarted. Run after the
 * commit, a reload holds no row lock and waits for none, and a rolled-back change reloads nothing.
 */
@Slf4j
public final class PolicyReloadAfterCommit {

    private PolicyReloadAfterCommit() {
    }

    /**
     * Runs the reload after the current transaction commits, once however many changes of that transaction ask for it;
     * with no transaction it runs at once.
     */
    public static void schedule(Runnable reload) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()
                || !TransactionSynchronizationManager.isActualTransactionActive()) {
            reload.run();
            return;
        }
        for (TransactionSynchronization registered : TransactionSynchronizationManager.getSynchronizations()) {
            if (registered instanceof ReloadOnCommit) {
                return;
            }
        }
        TransactionSynchronizationManager.registerSynchronization(new ReloadOnCommit(reload));
    }

    private record ReloadOnCommit(Runnable reload) implements TransactionSynchronization {

        @Override
        public void afterCommit() {
            try {
                reload.run();
            } catch (RuntimeException e) {
                log.error("Policy reload after commit failed; the policies loaded before stay in force until the next reload",
                        e);
            }
        }
    }
}
