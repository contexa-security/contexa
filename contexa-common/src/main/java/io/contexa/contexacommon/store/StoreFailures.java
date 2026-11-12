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

import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.dao.RecoverableDataAccessException;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.lang.Nullable;
import org.springframework.transaction.CannotCreateTransactionException;

import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.sql.SQLRecoverableException;
import java.sql.SQLTransientException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Tells a store that did not do its work from an answer it gave. A failure here says nothing about the user or the
 * request, so it is never taken for a refusal. A wrong script, a broken constraint or a value that cannot be read is not
 * one of these: such a failure stays what it is.
 */
public final class StoreFailures {

    /** Read by name: the Redis client is an optional dependency, and Jedis fails as Spring's own types. */
    private static final Set<String> LETTUCE_OUTAGES = Set.of("io.lettuce.core.RedisConnectionException",
            "io.lettuce.core.RedisCommandTimeoutException", "io.lettuce.core.RedisException");

    /**
     * Redisson's client, read by name too. A Redis that cannot be reached or does not answer is an outage; a connection pool
     * that has none to give, or a command Redis refused, is not.
     */
    private static final Set<String> REDISSON_OUTAGES = Set.of("org.redisson.client.RedisConnectionException",
            "org.redisson.client.WriteRedisConnectionException", "org.redisson.client.RedisResponseTimeoutException");

    /** SQLSTATE classes of a database that cannot serve: connection, a read-only transaction, resources, shutdown, system. */
    private static final Set<String> SQL_STATE_CLASSES = Set.of("08", "25", "53", "57", "58");

    private StoreFailures() {
    }

    /** Whether the failure, or one of its causes, is a store that did not do its work. */
    public static boolean isStoreFailure(@Nullable Throwable failure) {
        return anyCause(failure, StoreFailures::outage);
    }

    /** Whether the failure is an outage a gate already reported, so that its catcher has nothing to add. */
    public static boolean isReportedOutage(@Nullable Throwable failure) {
        return anyCause(failure, StoreUnavailableException.class::isInstance);
    }

    /** Whether the failure, or one of its causes, was raised by the driver or the pool, whatever it says. */
    static boolean isJdbcFailure(@Nullable Throwable failure) {
        return anyCause(failure, SQLException.class::isInstance);
    }

    private static boolean anyCause(@Nullable Throwable failure, Predicate<Throwable> test) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable cause = failure; cause != null && seen.add(cause); cause = cause.getCause()) {
            if (test.test(cause)) {
                return true;
            }
        }
        return false;
    }

    private static boolean outage(Throwable failure) {
        return failure instanceof DataAccessResourceFailureException
                || failure instanceof TransientDataAccessResourceException
                || failure instanceof QueryTimeoutException
                || failure instanceof RecoverableDataAccessException
                || failure instanceof CannotCreateTransactionException
                || LETTUCE_OUTAGES.contains(failure.getClass().getName())
                || REDISSON_OUTAGES.contains(failure.getClass().getName())
                || (failure instanceof SQLException sql && sqlOutage(sql));
    }

    private static boolean sqlOutage(SQLException failure) {
        if (failure instanceof SQLTransientException || failure instanceof SQLRecoverableException
                || failure instanceof SQLNonTransientConnectionException) {
            return true;
        }
        String state = failure.getSQLState();
        return state != null && state.length() >= 2 && SQL_STATE_CLASSES.contains(state.substring(0, 2));
    }
}
