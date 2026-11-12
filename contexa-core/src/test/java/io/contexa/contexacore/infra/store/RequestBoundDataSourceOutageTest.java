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
package io.contexa.contexacore.infra.store;

import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacommon.store.RequestBoundDataSource;
import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexacommon.store.StoreFailures;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.net.ServerSocket;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.Callable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

/**
 * Q-7 (PR-51, PR-55, PR-56) on a real database that stops, runs out of connections, holds a lock and freezes. A request
 * waits about a second once and then not at all; the engine keeps the pool's own wait; and everything comes back by
 * itself. The pool here waits three seconds, as the one of an application waits a minute, and asks a connection that
 * rested whether it lives for a second, as Contexa's own pool does (PR-198).
 */
class RequestBoundDataSourceOutageTest {

    private static final long POOL_WAIT_MILLIS = 3000L;
    private static final Duration REQUEST_LIMIT = Duration.ofMillis(1800);
    private static final int PORT = freePort();

    private static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse("postgres:16-alpine"))
            .withEnv("POSTGRES_PASSWORD", "outage").withEnv("POSTGRES_DB", "outage")
            .withExposedPorts(5432)
            .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2))
            .withCreateContainerCmdModifier(command -> {
                command.withName("p3infra-postgres-" + UUID.randomUUID());
                command.getHostConfig().withPortBindings(new PortBinding(Ports.Binding.bindPort(PORT), ExposedPort.tcp(5432)));
            });

    private HikariDataSource pool;
    private ContexaStores stores;
    private RequestBoundDataSource dataSource;

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void connect() throws Exception {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:postgresql://127.0.0.1:" + PORT + "/outage");
        config.setUsername("postgres");
        config.setPassword("outage");
        config.setMaximumPoolSize(2);
        config.setMinimumIdle(1);
        config.setConnectionTimeout(POOL_WAIT_MILLIS);
        config.setValidationTimeout(1000L);
        pool = new HikariDataSource(config);
        stores = new ContexaStores();
        dataSource = new RequestBoundDataSource(pool, stores.database());
        try (Connection connection = pool.getConnection(); Statement statement = connection.createStatement()) {
            statement.execute("create table if not exists decisions (id int)");
        }
    }

    @AfterEach
    void close() {
        RequestContextHolder.resetRequestAttributes();
        var state = POSTGRES.getDockerClient().inspectContainerCmd(POSTGRES.getContainerId()).exec().getState();
        if (Boolean.TRUE.equals(state.getPaused())) {
            POSTGRES.getDockerClient().unpauseContainerCmd(POSTGRES.getContainerId()).exec();
        } else if (!Boolean.TRUE.equals(state.getRunning())) {
            POSTGRES.getDockerClient().startContainerCmd(POSTGRES.getContainerId()).exec();
        }
        stores.destroy();
        pool.close();
    }

    private static void onARequestThread() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
    }

    private static <T> Duration took(Callable<T> work) {
        long began = System.nanoTime();
        try {
            work.call();
        } catch (Exception expected) {
            // The time is what is asked for here.
        }
        return Duration.ofNanos(System.nanoTime() - began);
    }

    private Connection connection() throws SQLException {
        return dataSource.getConnection();
    }

    private void stopDatabaseContainer() {
        POSTGRES.getDockerClient().stopContainerCmd(POSTGRES.getContainerId()).exec();
    }

    private void awaitGateUp() {
        await().atMost(Duration.ofSeconds(40)).pollInterval(Duration.ofMillis(200)).until(() -> !stores.database().isDown());
    }

    @Test
    @DisplayName("a request reads as it did while the database answers")
    void aRequestReadsWhileTheDatabaseAnswers() throws Exception {
        onARequestThread();

        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            assertThat(statement.execute("select 1")).isTrue();
        }
        assertThat(stores.database().isDown()).isFalse();
    }

    @Test
    @DisplayName("a stopped database costs one request about a second, the next none, and comes back by itself")
    void aStoppedDatabase() throws Exception {
        onARequestThread();
        stopDatabaseContainer();

        assertThat(took(this::connection)).as("the first request").isLessThan(REQUEST_LIMIT);
        assertThat(stores.database().isDown()).isTrue();
        assertThat(took(this::connection)).as("while the gate is down").isLessThan(Duration.ofMillis(100));
        assertThatThrownBy(this::connection).satisfies(failure -> {
            assertThat(StoreFailures.isStoreFailure(failure)).isTrue();
            assertThat(StoreFailures.isReportedOutage(failure)).as("the gate reported it, nobody else has to").isTrue();
        });

        POSTGRES.getDockerClient().startContainerCmd(POSTGRES.getContainerId()).exec();
        awaitGateUp();

        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            assertThat(statement.execute("select 1")).isTrue();
        }
    }

    @Test
    @DisplayName("the engine's threads keep the pool's wait")
    void theEngineKeepsThePoolsWait() {
        stopDatabaseContainer();

        Duration took = took(this::connection);

        assertThat(took).as("a thread that serves no request waits as the pool says").isGreaterThan(Duration.ofMillis(POOL_WAIT_MILLIS - 500));
        assertThat(stores.database().isDown()).as("and lowers no gate on the way").isFalse();
    }

    @Test
    @DisplayName("a pool that is used up costs a request about a second, and the gate rises when a connection is free")
    void aPoolThatIsUsedUp() throws Exception {
        Connection first = pool.getConnection();
        Connection second = pool.getConnection();
        onARequestThread();
        try {
            assertThat(took(this::connection)).isLessThan(REQUEST_LIMIT);
            assertThat(stores.database().isDown()).isTrue();
        } finally {
            first.close();
            second.close();
        }

        awaitGateUp();
    }

    @Test
    @DisplayName("Contexa's own statement behind a lock ends in about a second; the pool has its connection back")
    void aStatementBehindALock() throws Exception {
        try (Connection locking = pool.getConnection(); Statement lock = locking.createStatement()) {
            locking.setAutoCommit(false);
            lock.execute("lock table decisions in access exclusive mode");
            onARequestThread();
            RequestPathScope.enter();
            try {
                Duration took = took(() -> {
                    try (Connection connection = connection(); Statement statement = connection.createStatement()) {
                        return statement.execute("insert into decisions values (1)");
                    }
                });
                assertThat(took).isLessThan(REQUEST_LIMIT.plusMillis(500));
            } finally {
                RequestPathScope.leave();
            }
            locking.rollback();
        }
        RequestContextHolder.resetRequestAttributes();
        try (Connection connection = pool.getConnection(); Statement statement = connection.createStatement()) {
            assertThat(statement.execute("select 1")).isTrue();
        }
    }

    @Test
    @DisplayName("only Contexa's own work of a protected call gets the statement limit, and the pool takes it off again")
    void theStatementLimitStaysInContexasWork() throws Exception {
        onARequestThread();
        try (Connection plain = connection()) {
            assertThat(plain.getNetworkTimeout()).as("a console page or the application's method").isZero();
        }

        RequestPathScope.enter();
        try (Connection own = connection()) {
            assertThat(own.getNetworkTimeout()).isEqualTo(1000);
        } finally {
            RequestPathScope.leave();
        }

        try (Connection again = connection()) {
            assertThat(again.getNetworkTimeout()).as("the same connection, back from the pool").isZero();
        }
    }

    @Test
    @DisplayName("a frozen database, which takes a statement and answers nothing, ends Contexa's statement in about a second")
    void aFrozenDatabase() throws Exception {
        onARequestThread();
        RequestPathScope.enter();
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            POSTGRES.getDockerClient().pauseContainerCmd(POSTGRES.getContainerId()).exec();

            assertThat(took(() -> statement.execute("select 1"))).isLessThan(REQUEST_LIMIT.plusMillis(500));
        } finally {
            RequestPathScope.leave();
            POSTGRES.getDockerClient().unpauseContainerCmd(POSTGRES.getContainerId()).exec();
        }
    }

    @Test
    @DisplayName("a database that froze while the pool's connections rested costs one request about a second, the next none (PR-198)")
    void aDatabaseThatFrozeWhileTheConnectionsRested() throws Exception {
        onARequestThread();
        // The pool asks a connection whether it lives once it rested for half a second, and waits for that answer.
        Thread.sleep(700L);
        POSTGRES.getDockerClient().pauseContainerCmd(POSTGRES.getContainerId()).exec();

        assertThat(took(this::connection)).as("the first request").isLessThan(REQUEST_LIMIT);
        assertThat(stores.database().isDown()).isTrue();
        assertThat(took(this::connection)).as("while the gate is down").isLessThan(Duration.ofMillis(100));

        POSTGRES.getDockerClient().unpauseContainerCmd(POSTGRES.getContainerId()).exec();
        awaitGateUp();

        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            assertThat(statement.execute("select 1")).isTrue();
        }
    }
}
