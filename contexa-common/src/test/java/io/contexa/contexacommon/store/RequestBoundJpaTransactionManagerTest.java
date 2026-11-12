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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * PR-200: while Contexa's database is known to be down a request's transaction ends before it asks the pool for
 * anything, in the failure it always ended in; the engine's threads and a database that answers are left as they were.
 */
class RequestBoundJpaTransactionManagerTest {

    private final ContexaStores stores = new ContexaStores();
    private final EntityManagerFactory factory = mock(EntityManagerFactory.class);
    private final RequestBoundJpaTransactionManager transactions =
            new RequestBoundJpaTransactionManager(factory, stores.database());

    @AfterEach
    void stop() {
        RequestContextHolder.resetRequestAttributes();
        stores.destroy();
    }

    private void databaseDown() {
        stores.database().watchWith(() -> {
            throw new IllegalStateException("still down");
        });
        stores.database().fail(new QueryTimeoutException("no answer"));
        assertThat(stores.database().isDown()).isTrue();
    }

    private static void onARequestThread() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
    }

    @Test
    @DisplayName("a request's transaction is refused before the factory or the pool is asked for anything")
    void aRequestsTransactionIsRefusedBeforeThePool() {
        databaseDown();
        onARequestThread();

        Throwable refusal = catchThrowable(() -> transactions.getTransaction(new DefaultTransactionDefinition()));

        assertThat(refusal).isInstanceOf(CannotCreateTransactionException.class)
                .hasMessageContaining("Contexa's database is unavailable");
        assertThat(StoreFailures.isStoreFailure(refusal)).as("read as an outage, as it always was").isTrue();
        assertThat(StoreFailures.isReportedOutage(refusal)).as("the gate has told it, the catcher need not").isTrue();
        verify(factory, never()).createEntityManager();
    }

    @Test
    @DisplayName("a thread that serves no request starts its transaction as before, gate down or not")
    void theEnginesThreadsStartTheirsAsBefore() {
        databaseDown();

        catchThrowable(() -> transactions.getTransaction(new DefaultTransactionDefinition()));

        verify(factory).createEntityManager();
    }

    @Test
    @DisplayName("a request's transaction starts as before while the database answers")
    void aRequestsTransactionStartsWhileTheDatabaseAnswers() {
        onARequestThread();

        catchThrowable(() -> transactions.getTransaction(new DefaultTransactionDefinition()));

        verify(factory).createEntityManager();
    }
}
