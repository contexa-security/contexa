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
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.TransactionDefinition;

/**
 * Contexa's transactions as a request starts them (PR-200). While the gate is down {@link RequestBoundDataSource} refuses
 * a request thread its connection at once, and a transaction that went as far as asking for one had Hibernate write the
 * refusal to the log as an SQL error: two lines for every transaction of every request of the outage. A request's
 * transaction is refused here instead, before anything is asked of the pool, with the failure it ended in all along.
 * Threads that serve no request start theirs as before.
 */
public class RequestBoundJpaTransactionManager extends JpaTransactionManager {

    private final StoreGate gate;

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
}
