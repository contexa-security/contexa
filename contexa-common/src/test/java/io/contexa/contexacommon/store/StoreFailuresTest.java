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

import io.lettuce.core.RedisCommandExecutionException;
import io.lettuce.core.RedisCommandTimeoutException;
import io.lettuce.core.RedisConnectionException;
import io.lettuce.core.RedisException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.RedisSystemException;
import org.springframework.transaction.CannotCreateTransactionException;

import java.sql.SQLException;
import java.sql.SQLTransientConnectionException;

import static org.assertj.core.api.Assertions.assertThat;

/** Only a store that did not do its work counts: a mistake in a script or in the data stays what it is. */
class StoreFailuresTest {

    @Test
    @DisplayName("a transaction the pool could not open is a store failure, however deep the cause")
    void aTransactionThatCouldNotOpen() {
        Exception failure = new IllegalStateException("Event processing failed", new CannotCreateTransactionException("no connection"));

        assertThat(StoreFailures.isStoreFailure(failure)).isTrue();
    }

    @Test
    @DisplayName("the failures of Redis as Spring Data and Lettuce report them")
    void redisFailures() {
        assertThat(StoreFailures.isStoreFailure(new RedisConnectionFailureException("Unable to connect"))).isTrue();
        assertThat(StoreFailures.isStoreFailure(new QueryTimeoutException("Redis command timed out"))).isTrue();
        assertThat(StoreFailures.isStoreFailure(new RedisSystemException("Error in execution",
                new RedisException("Currently not connected. Commands are rejected.")))).isTrue();
        assertThat(StoreFailures.isStoreFailure(new RedisCommandTimeoutException("timed out"))).isTrue();
        assertThat(StoreFailures.isStoreFailure(new RedisConnectionException("refused"))).isTrue();
    }

    @Test
    @DisplayName("a command Redis answered with an error is no outage")
    void aCommandRedisRefusedIsNoOutage() {
        assertThat(StoreFailures.isStoreFailure(new RedisSystemException("Error in execution",
                new RedisCommandExecutionException("ERR wrong number of arguments")))).isFalse();
    }

    @Test
    @DisplayName("a database that cannot serve: no connection, read only, too many connections, shut down")
    void aDatabaseThatCannotServe() {
        assertThat(StoreFailures.isStoreFailure(new SQLTransientConnectionException("HikariPool-2 - Connection is not available"))).isTrue();
        assertThat(StoreFailures.isStoreFailure(new SQLException("connection refused", "08001"))).isTrue();
        assertThat(StoreFailures.isStoreFailure(new SQLException("cannot execute INSERT in a read-only transaction", "25006"))).isTrue();
        assertThat(StoreFailures.isStoreFailure(new SQLException("too many connections for role", "53300"))).isTrue();
        assertThat(StoreFailures.isStoreFailure(new SQLException("the database system is starting up", "57P03"))).isTrue();
    }

    @Test
    @DisplayName("what the data or the statement got wrong is no store failure")
    void aMistakeIsNoStoreFailure() {
        assertThat(StoreFailures.isStoreFailure(new SQLException("duplicate key", "23505"))).isFalse();
        assertThat(StoreFailures.isStoreFailure(new SQLException("syntax error", "42601"))).isFalse();
        assertThat(StoreFailures.isStoreFailure(new DataIntegrityViolationException("duplicate key"))).isFalse();
        assertThat(StoreFailures.isStoreFailure(new OptimisticLockingFailureException("changed by another"))).isFalse();
        assertThat(StoreFailures.isStoreFailure(new IllegalStateException("a bug"))).isFalse();
        assertThat(StoreFailures.isStoreFailure(null)).isFalse();
    }

    @Test
    @DisplayName("a cycle in the causes ends")
    void aCycleEnds() {
        IllegalStateException first = new IllegalStateException("first");
        IllegalStateException second = new IllegalStateException("second", first);
        first.initCause(second);

        assertThat(StoreFailures.isStoreFailure(first)).isFalse();
    }

    @Test
    @DisplayName("an outage a gate reported is told from one nobody reported")
    void aReportedOutage() {
        assertThat(StoreFailures.isReportedOutage(new StoreUnavailableException("Redis"))).isTrue();
        assertThat(StoreFailures.isReportedOutage(new SQLTransientConnectionException("down", new StoreUnavailableException("db")))).isTrue();
        assertThat(StoreFailures.isReportedOutage(new QueryTimeoutException("Redis command timed out"))).isFalse();
        assertThat(StoreFailures.isStoreFailure(new StoreUnavailableException("Redis"))).isTrue();
    }

    @Test
    @DisplayName("an outage a gate reported carries no stack: it is met by every request of the outage")
    void aReportedOutageCarriesNoStack() {
        assertThat(new StoreUnavailableException("Redis").getStackTrace()).isEmpty();
    }
}
