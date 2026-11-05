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

import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import com.zaxxer.hikari.pool.HikariPool;
import org.springframework.jdbc.datasource.DelegatingDataSource;
import org.springframework.util.ClassUtils;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLTransientConnectionException;
import java.time.Duration;

/**
 * Contexa's own pool as a request sees it. The pool's wait, a minute by default, stays for the engine's long work; a
 * thread that serves a request waits about a second for a connection, and not at all while the gate is down (PR-51).
 * Inside a protected call a connection also stops waiting for a database that took the statement and does not answer,
 * a lock held on a table or a machine that froze, instead of holding the request until the socket gives up; the method
 * of the application is not touched by that. A failed wait lowers the gate, and the gate raises itself.
 */
public final class RequestBoundDataSource extends DelegatingDataSource implements AutoCloseable {

    private static final Duration REQUEST_WAIT = Duration.ofSeconds(1);
    private static final boolean HIKARI = ClassUtils.isPresent("com.zaxxer.hikari.pool.HikariPool",
            RequestBoundDataSource.class.getClassLoader());

    private final StoreGate gate;

    public RequestBoundDataSource(DataSource pool, StoreGate gate) {
        super(pool);
        this.gate = gate;
        gate.watchWith(this::look);
    }

    @Override
    public Connection getConnection() throws SQLException {
        if (!RequestPathScope.onRequestThread()) {
            return super.getConnection();
        }
        if (gate.isDown()) {
            throw new SQLTransientConnectionException(gate.name() + " is unavailable", gate.unavailable());
        }
        try {
            Connection connection = waitBounded();
            if (RequestPathScope.inContexaWork()) {
                boundStatements(connection);
            }
            return connection;
        } catch (SQLException failure) {
            gate.fail(failure);
            throw failure;
        }
    }

    private Connection waitBounded() throws SQLException {
        return HIKARI ? HikariWait.connection(obtainTargetDataSource()) : super.getConnection();
    }

    private static void boundStatements(Connection connection) throws SQLException {
        try {
            connection.setNetworkTimeout(Runnable::run, (int) REQUEST_WAIT.toMillis());
        } catch (SQLFeatureNotSupportedException driverWithoutIt) {
            // The driver keeps its own waits: the connection wait above is what is bounded then.
        }
    }

    /** The pool is closed with this bean, as it was when the pool itself was the bean. */
    @Override
    public void close() throws Exception {
        if (obtainTargetDataSource() instanceof AutoCloseable pool) {
            pool.close();
        }
    }

    private void look() throws SQLException {
        try (Connection connection = waitBounded()) {
            if (!connection.isValid((int) REQUEST_WAIT.toSeconds())) {
                throw new SQLTransientConnectionException(gate.name() + " does not answer");
            }
        }
    }

    /** Kept apart so that an application on another pool never loads a Hikari type. */
    private static final class HikariWait {

        static Connection connection(DataSource pool) throws SQLException {
            if (pool instanceof HikariDataSource hikari) {
                HikariPoolMXBean running = hikari.getHikariPoolMXBean();
                if (running instanceof HikariPool started) {
                    return started.getConnection(REQUEST_WAIT.toMillis());
                }
            }
            return pool.getConnection();
        }
    }
}
