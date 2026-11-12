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

import jakarta.persistence.EntityManagerFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.DefaultTransactionStatus;

import java.sql.SQLNonTransientConnectionException;

/**
 * Contexa's transactions as a request starts them (PR-200). While the gate is down {@link RequestBoundDataSource} refuses
 * a request thread its connection at once, and a transaction that went as far as asking for one had Hibernate write the
 * refusal to the log as an SQL error: two lines for every transaction of every request of the outage. A request's
 * transaction is refused here instead, before anything is asked of the pool, with the failure it ended in all along.
 * Threads that serve no request start theirs as before.
 *
 * <p>A connection that breaks under a statement is closed by the pool before the rollback reaches it. The rollback that
 * could not be sent was thrown in place of the failure that ended the transaction: that failure went to the log with its
 * stack, once for every transaction the outage caught, whoever caught the other one could not tell a database that does
 * not answer, and the gate, which hears of a connection that is not given but not of one that is lost, stayed up while
 * the same request waited for the pool once more. Nothing is committed on a connection that is gone; such a transaction
 * ends in the failure it had, and the gate is told.
 */
@Slf4j
public class RequestBoundJpaTransactionManager extends JpaTransactionManager {

    private final StoreGate gate;
    private final RepeatedFailure lostRollbacks = new RepeatedFailure();

    public RequestBoundJpaTransactionManager(EntityManagerFactory entityManagerFactory, StoreGate gate) {
        super(entityManagerFactory);
        this.gate = gate;
    }

    @Override
    protected void doBegin(Object transaction, TransactionDefinition definition) {
        if (RequestPathScope.onRequestThread() && gate.isDown()) {
            throw new CannotCreateTransactionException(gate.name() + " is unavailable", gate.unavailable());
        }
        super.doBegin(transaction, definition);
    }

    @Override
    protected void doRollback(DefaultTransactionStatus status) {
        try {
            super.doRollback(status);
        } catch (RuntimeException failure) {
            if (!StoreFailures.isJdbcFailure(failure)) {
                throw failure;
            }
            gate.fail(new SQLNonTransientConnectionException("A transaction lost its connection before its rollback",
                    failure));
            long unreported = lostRollbacks.count();
            if (unreported > 0) {
                Throwable root = NestedExceptionUtils.getMostSpecificCause(failure);
                log.warn("[Contexa] {} transactions of Contexa's lost their connection before they could be rolled back "
                        + "since this was last said ({}: {}). Nothing of them was committed; each ended in the failure it "
                        + "had.", unreported, root.getClass().getSimpleName(), root.getMessage());
            }
        }
    }
}
