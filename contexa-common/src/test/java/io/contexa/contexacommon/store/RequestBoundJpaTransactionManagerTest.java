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

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.EntityTransaction;
import jakarta.persistence.PersistenceException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.orm.jpa.JpaSystemException;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PR-200: while Contexa's database is known to be down a request's transaction ends before it asks the pool for
 * anything, in the failure it always ended in; the engine's threads and a database that answers are left as they were.
 * A transaction whose connection broke ends in the failure that broke it, not in the rollback that could not be sent,
 * and the gate hears of the connection.
 */
@ExtendWith(OutputCaptureExtension.class)
class RequestBoundJpaTransactionManagerTest {

    private static final String LOST = "lost their connection before they could be rolled back";

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

    private EntityTransaction aTransactionWhoseRollbackFailsWith(RuntimeException failure) {
        EntityManager entityManager = mock(EntityManager.class);
        EntityTransaction transaction = mock(EntityTransaction.class);
        when(factory.createEntityManager()).thenReturn(entityManager);
        when(entityManager.getTransaction()).thenReturn(transaction);
        when(transaction.isActive()).thenReturn(true);
        doThrow(failure).when(transaction).rollback();
        return transaction;
    }

    private static PersistenceException aClosedConnection() {
        return new PersistenceException("Unable to rollback against JDBC Connection",
                new SQLException("Connection is closed"));
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

    @Test
    @DisplayName("a rollback its lost connection could not take leaves the transaction to the failure that ended it")
    void aRollbackTheLostConnectionCouldNotTakeIsNotThrown() {
        EntityTransaction transaction = aTransactionWhoseRollbackFailsWith(aClosedConnection());
        TransactionStatus status = transactions.getTransaction(new DefaultTransactionDefinition());

        assertThatCode(() -> transactions.rollback(status)).doesNotThrowAnyException();

        verify(transaction).rollback();
        assertThat(status.isCompleted()).isTrue();
    }

    @Test
    @DisplayName("the gate hears of the lost connection, and a request's next transaction does not wait for the pool")
    void theGateHearsOfTheLostConnection() {
        stores.database().watchWith(() -> {
            throw new IllegalStateException("still down");
        });
        aTransactionWhoseRollbackFailsWith(aClosedConnection());
        onARequestThread();
        TransactionStatus status = transactions.getTransaction(new DefaultTransactionDefinition());

        transactions.rollback(status);

        assertThat(stores.database().isDown()).isTrue();
        Throwable refusal = catchThrowable(() -> transactions.getTransaction(new DefaultTransactionDefinition()));
        assertThat(refusal).isInstanceOf(CannotCreateTransactionException.class);
        verify(factory, times(1)).createEntityManager();
    }

    @Test
    @DisplayName("a rollback that failed for another reason is thrown as before, and the gate stays up")
    void aRollbackThatFailedForAnotherReasonIsThrown() {
        stores.database().watchWith(() -> {
        });
        aTransactionWhoseRollbackFailsWith(new PersistenceException("a listener refused the rollback"));
        TransactionStatus status = transactions.getTransaction(new DefaultTransactionDefinition());

        Throwable failure = catchThrowable(() -> transactions.rollback(status));

        assertThat(failure).isInstanceOf(JpaSystemException.class).hasMessageContaining("a listener refused the rollback");
        assertThat(stores.database().isDown()).isFalse();
    }

    @Test
    @DisplayName("rollbacks that lost their connection are told once, by cause and without a stack for each")
    void rollbacksThatLostTheirConnectionAreToldOnce(CapturedOutput output) {
        aTransactionWhoseRollbackFailsWith(aClosedConnection());

        for (int lost = 0; lost < 300; lost++) {
            transactions.rollback(transactions.getTransaction(new DefaultTransactionDefinition()));
        }

        assertThat(StringUtils.countOccurrencesOf(output.getAll(), LOST)).isEqualTo(1);
        assertThat(output.getAll()).contains("SQLException: Connection is closed")
                .doesNotContain("at io.contexa.contexacommon.store.RequestBoundJpaTransactionManager");
    }
}
