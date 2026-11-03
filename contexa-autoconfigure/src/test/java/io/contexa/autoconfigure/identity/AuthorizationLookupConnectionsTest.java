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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.AuthContextProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLTransientConnectionException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent RL-15. Reading a stored authorization maps its row while the query still holds its connection, and the row
 * mapper looks the registered client up with a second query. A burst of requests with a bearer token (an agent sending
 * dozens at once) therefore made every thread of a pool hold one connection and wait for a second one: the pool of the
 * engine stood still until the connection timeout (60 seconds) ended the waits. The lookups must hold one connection
 * each, so that a pool of any size serves any number of simultaneous callers.
 */
class AuthorizationLookupConnectionsTest {

    private static final int POOL = 4;
    private static final int CALLERS = 24;
    private static final String TOKEN = "access-token-of-the-burst";

    private BoundedDataSource dataSource;
    private OAuth2AuthorizationService service;
    private JdbcTemplate jdbcTemplate;
    private RegisteredClient client;

    @BeforeEach
    void setUp() {
        // The lookups of the burst are the only users of this pool, as the requests of an agent are at the engine.
        dataSource = new BoundedDataSource("jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                POOL, Duration.ofSeconds(4));
        jdbcTemplate = new JdbcTemplate(dataSource);
        TransactionTemplate transactionTemplate = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setIssuerUri("https://issuer.example.test");
        properties.getOauth2().setClientSecret("burst-test-unique-client-secret");
        IdentityOAuth2AutoConfiguration configuration = new IdentityOAuth2AutoConfiguration(transactionTemplate,
                properties);
        new ResourceDatabasePopulator(new ClassPathResource("contexa-oauth2-authorization-schema.sql"))
                .execute(dataSource);
        RegisteredClientRepository repository = configuration.registeredClientRepository(jdbcTemplate);
        client = repository.findByClientId(properties.getOauth2().getClientId());
        service = configuration.authorizationService(jdbcTemplate, repository);
        service.save(authorization("stored-1", TOKEN));
        for (int i = 1; i <= CALLERS; i++) {
            service.save(authorization("stored-update-" + i, "token-update-" + i));
        }
        dataSource.resetCounters();
    }

    @AfterEach
    void tearDown() {
        dataSource.release();
        jdbcTemplate.execute("SHUTDOWN");
    }

    // LC-01
    @Test
    void simultaneousTokenLookupsEachHoldOneConnectionAndAllAreServed() throws Exception {
        List<Object> outcomes = together(CALLERS, () -> service.findByToken(TOKEN, OAuth2TokenType.ACCESS_TOKEN));

        assertThat(outcomes).hasSize(CALLERS).allSatisfy(outcome -> assertThat(outcome).isInstanceOf(OAuth2Authorization.class));
        assertThat(dataSource.mostHeldByOneThread()).as("connections one lookup holds at once").isEqualTo(1);
        assertThat(dataSource.refusals()).as("lookups that waited in vain for a connection").isZero();
    }

    // LC-02
    @Test
    void simultaneousLookupsById() throws Exception {
        List<Object> outcomes = together(CALLERS, () -> service.findById("stored-1"));

        assertThat(outcomes).hasSize(CALLERS).allSatisfy(outcome -> assertThat(outcome).isInstanceOf(OAuth2Authorization.class));
        assertThat(dataSource.mostHeldByOneThread()).isEqualTo(1);
        assertThat(dataSource.refusals()).isZero();
    }

    // LC-03: a refresh saves an authorization that is already stored, and the delegate reads it before it writes
    @Test
    void simultaneousSavesOfStoredAuthorizations() throws Exception {
        AtomicInteger number = new AtomicInteger();
        List<Object> outcomes = together(CALLERS, () -> {
            int i = number.incrementAndGet();
            service.save(authorization("stored-update-" + i, "token-rotated-" + i));
            return "saved";
        });

        assertThat(outcomes).hasSize(CALLERS).allSatisfy(outcome -> assertThat(outcome).isEqualTo("saved"));
        assertThat(dataSource.mostHeldByOneThread()).isEqualTo(1);
        assertThat(dataSource.refusals()).isZero();
        assertThat(service.findByToken("token-rotated-7", OAuth2TokenType.ACCESS_TOKEN)).isNotNull();
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM ctxa_oauth2_authorization", Integer.class))
                .isEqualTo(CALLERS + 1);
    }

    // LC-04
    @Test
    void theLookupAnswersWhatWasStored() {
        OAuth2Authorization found = service.findByToken(TOKEN, OAuth2TokenType.ACCESS_TOKEN);

        assertThat(found).isNotNull();
        assertThat(found.getId()).isEqualTo("stored-1");
        assertThat(found.getRegisteredClientId()).isEqualTo(client.getId());
        assertThat(found.getAccessToken().getToken().getTokenValue()).isEqualTo(TOKEN);
        assertThat(service.findByToken("unknown-token", OAuth2TokenType.ACCESS_TOKEN)).isNull();
        assertThat(service.findById("unknown-id")).isNull();
    }

    // LC-05: a lookup made inside a transaction of its caller joins it and holds that one connection
    @Test
    void aLookupInsideACallersTransactionStaysOnTheCallersConnection() {
        TransactionTemplate caller = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        Object found = caller.execute(status -> service.findByToken(TOKEN, OAuth2TokenType.ACCESS_TOKEN));

        assertThat(found).isNotNull();
        assertThat(dataSource.mostHeldByOneThread()).isEqualTo(1);
    }

    private OAuth2Authorization authorization(String id, String tokenValue) {
        Instant now = Instant.now();
        return OAuth2Authorization.withRegisteredClient(client)
                .id(id)
                .principalName("agent-" + id)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokenValue, now, now.plusSeconds(600)))
                .build();
    }

    /** All callers start together; one that does not end in a minute is a deadlock. */
    private List<Object> together(int callers, Callable<Object> call) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(callers);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Object>> futures = new ArrayList<>();
        for (int i = 0; i < callers; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                try {
                    return call.call();
                } catch (Exception failure) {
                    return failure;
                }
            }));
        }
        start.countDown();
        List<Object> outcomes = new ArrayList<>();
        try {
            for (Future<Object> future : futures) {
                outcomes.add(future.get(60, TimeUnit.SECONDS));
            }
        } finally {
            pool.shutdownNow();
        }
        return outcomes;
    }

    /**
     * A pool of a fixed size: a caller waits for a free connection for the timeout and is then refused, as the pool of
     * the engine does. It counts the connections each thread holds at once.
     */
    static final class BoundedDataSource implements DataSource {

        private final DriverManagerDataSource real;
        private final Semaphore free;
        private final Duration timeout;
        private final ThreadLocal<int[]> held = ThreadLocal.withInitial(() -> new int[1]);
        private final AtomicInteger mostHeld = new AtomicInteger();
        private final AtomicInteger refusals = new AtomicInteger();

        BoundedDataSource(String url, int size, Duration timeout) {
            this.real = new DriverManagerDataSource(url, "sa", "");
            this.free = new Semaphore(size);
            this.timeout = timeout;
        }

        void resetCounters() {
            mostHeld.set(0);
            refusals.set(0);
        }

        int mostHeldByOneThread() {
            return mostHeld.get();
        }

        int refusals() {
            return refusals.get();
        }

        void release() {
            // the connections of a deadlocked run end with the test
        }

        @Override
        public Connection getConnection() throws SQLException {
            try {
                if (!free.tryAcquire(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                    refusals.incrementAndGet();
                    throw new SQLTransientConnectionException("Connection is not available, request timed out after "
                            + timeout.toMillis() + "ms");
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new SQLTransientConnectionException("Interrupted while waiting for a connection", interrupted);
            }
            Connection connection;
            try {
                connection = real.getConnection();
            } catch (SQLException | RuntimeException failure) {
                free.release();
                throw failure;
            }
            int[] count = held.get();
            count[0]++;
            mostHeld.accumulateAndGet(count[0], Math::max);
            boolean[] closed = new boolean[1];
            InvocationHandler handler = (proxy, method, args) -> {
                if (method.getName().equals("close") && args == null) {
                    if (!closed[0]) {
                        closed[0] = true;
                        held.get()[0]--;
                        free.release();
                        connection.close();
                    }
                    return null;
                }
                if (method.getName().equals("isClosed") && args == null) {
                    return closed[0] || connection.isClosed();
                }
                try {
                    return method.invoke(connection, args);
                } catch (InvocationTargetException failure) {
                    throw failure.getCause();
                }
            };
            return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                    new Class<?>[]{Connection.class}, handler);
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return getConnection();
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            throw new SQLException("not a wrapper");
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(int seconds) {
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException();
        }
    }
}
