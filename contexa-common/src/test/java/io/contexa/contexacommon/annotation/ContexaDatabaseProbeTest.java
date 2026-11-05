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
package io.contexa.contexacommon.annotation;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ContexaDatabaseProbeTest {

    private static final String URL = "jdbc:contexa-probe-test://db/engine";

    private final AtomicInteger attempts = new AtomicInteger();
    private final CountDownLatch released = new CountDownLatch(1);
    private final ScriptedDriver driver = new ScriptedDriver();
    private final ContexaDatabaseProbe probe = new ContexaDatabaseProbe(Duration.ofSeconds(20), Duration.ofMillis(20));
    private final ContexaDatabaseProbe shortWindow = new ContexaDatabaseProbe(Duration.ofMillis(600), Duration.ofMillis(20));

    private volatile int failuresBeforeAnswer;
    private volatile boolean hangs;
    private volatile Connection scripted;

    @BeforeEach
    void register() throws SQLException {
        DriverManager.registerDriver(driver);
    }

    @AfterEach
    void deregister() throws SQLException {
        released.countDown();
        DriverManager.deregisterDriver(driver);
    }

    private static StandardEnvironment environmentWith(Map<String, Object> properties) {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("test", properties));
        return environment;
    }

    private static StandardEnvironment database() {
        return environmentWith(Map.of("contexa.datasource.url", URL, "contexa.datasource.username", "u", "contexa.datasource.password", "secret-password"));
    }

    @Test
    void aDatabaseThatAnswersIsNoProblem() {
        assertThat(probe.problem(database())).isNull();
        assertThat(attempts).hasValue(1);
    }

    @Test
    void aDatabaseThatIsStillComingUpIsWaitedForWithinTheWindow() {
        failuresBeforeAnswer = 2;

        assertThat(probe.problem(database())).isNull();
        assertThat(attempts).hasValue(3);
    }

    @Test
    void aDatabaseThatRefusesIsAProblemAfterTheWindow() {
        failuresBeforeAnswer = Integer.MAX_VALUE;

        assertThat(shortWindow.problem(database())).contains("connection refused");
        assertThat(attempts.get()).isGreaterThan(1);
    }

    @Test
    void aDatabaseThatNeverAnswersIsAProblemAfterTheWindowAndNotLater() {
        hangs = true;
        long started = System.nanoTime();

        String problem = shortWindow.problem(database());

        assertThat(problem).isNotNull();
        assertThat(Duration.ofNanos(System.nanoTime() - started).toMillis()).isLessThan(5000);
    }

    @Test
    void theProblemNeverCarriesThePassword() {
        failuresBeforeAnswer = Integer.MAX_VALUE;

        assertThat(shortWindow.problem(database())).doesNotContain("secret-password");
    }

    @Test
    void withoutAnAddressThereIsNothingToAsk() {
        assertThat(probe.problem(environmentWith(Map.of()))).isNull();
        assertThat(attempts).hasValue(0);
    }

    @Test
    void anAddressNoDriverReadsIsLeftToTheNormalStart() {
        assertThat(probe.problem(environmentWith(Map.of("contexa.datasource.url", "jdbc:nobody://x/y")))).isNull();
    }

    @Test
    void anAddressWithAnUnresolvedPlaceholderIsLeftToTheNormalStart() {
        assertThat(probe.problem(environmentWith(Map.of("contexa.datasource.url", "${NOT_SET_ANYWHERE}")))).isNull();
    }

    /** PR-16: the database answered and the start then stopped on what the account may not create, with no word on what to do. */
    @Test
    void anExtensionTheAccountMayNotCreateIsAProblemThatNamesTheWayOut() throws SQLException {
        Statement statement = postgresConnection();
        when(statement.execute(contains("vector")))
                .thenThrow(new SQLException("permission denied to create extension \"vector\"", "42501"));

        String problem = probe.problem(database());

        assertThat(problem).contains("permission denied to create extension")
                .contains("CREATE EXTENSION \"vector\"");
    }

    @Test
    void anExtensionTheAccountMayNotCreateIsNotWaitedFor() throws SQLException {
        Statement statement = postgresConnection();
        when(statement.execute(contains("vector")))
                .thenThrow(new SQLException("permission denied to create extension \"vector\"", "42501"));

        assertThat(probe.problem(database())).isNotNull();
        assertThat(attempts).as("waiting changes nothing about what the account may do").hasValue(1);
    }

    @Test
    void askingLeavesNothingBehindInTheDatabase() throws SQLException {
        Statement statement = postgresConnection();

        assertThat(probe.problem(database())).isNull();

        verify(statement).execute("create extension if not exists \"vector\"");
        verify(statement).execute("create extension if not exists \"hstore\"");
        verify(statement).execute("create extension if not exists \"uuid-ossp\"");
        verify(scripted).setAutoCommit(false);
        verify(scripted).rollback();
        verify(scripted, never()).commit();
    }

    /** A database under migrations creates the vector table itself: the store then creates no extension of its own. */
    @Test
    void whereTheVectorStoreCreatesNothingOnlyTheSchemasExtensionIsAsked() throws SQLException {
        Statement statement = postgresConnection();

        assertThat(probe.problem(environmentWith(Map.of("contexa.datasource.url", URL,
                "contexa.vectorstore.pgvector.initialize-schema", "false")))).isNull();

        verify(statement).execute("create extension if not exists \"vector\"");
        verify(statement, never()).execute(contains("hstore"));
    }

    @Test
    void aDatabaseOfAnotherKindIsNotAskedForExtensions() throws SQLException {
        Statement statement = connection("H2");

        assertThat(probe.problem(database())).isNull();

        verify(statement, never()).execute(anyString());
    }

    private Statement postgresConnection() throws SQLException {
        return connection("PostgreSQL");
    }

    private Statement connection(String product) throws SQLException {
        Connection connection = mock(Connection.class);
        DatabaseMetaData metadata = mock(DatabaseMetaData.class);
        Statement statement = mock(Statement.class);
        when(connection.getMetaData()).thenReturn(metadata);
        when(metadata.getDatabaseProductName()).thenReturn(product);
        when(connection.createStatement()).thenReturn(statement);
        scripted = connection;
        return statement;
    }

    /** Answers, refuses or hangs as the test says, for its own address only. */
    private final class ScriptedDriver implements Driver {

        @Override
        public Connection connect(String url, Properties info) throws SQLException {
            if (!acceptsURL(url)) {
                return null;
            }
            int attempt = attempts.incrementAndGet();
            if (hangs) {
                try {
                    released.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            if (attempt <= failuresBeforeAnswer) {
                throw new SQLException("connection refused", "08001");
            }
            return scripted != null ? scripted : mock(Connection.class);
        }

        @Override
        public boolean acceptsURL(String url) {
            return url != null && url.startsWith("jdbc:contexa-probe-test:");
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
            return new DriverPropertyInfo[0];
        }

        @Override
        public int getMajorVersion() {
            return 1;
        }

        @Override
        public int getMinorVersion() {
            return 0;
        }

        @Override
        public boolean jdbcCompliant() {
            return false;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getGlobal();
        }
    }
}
