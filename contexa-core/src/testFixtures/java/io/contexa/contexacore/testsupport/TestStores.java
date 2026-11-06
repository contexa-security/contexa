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
package io.contexa.contexacore.testsupport;

import java.util.Optional;
import java.util.function.Function;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;

/**
 * The Redis and the PostgreSQL database a test may use, named by environment variables and by nothing else.
 *
 * <p>There is no default address. A developer's own Redis and database usually listen on {@code localhost:6379} and
 * {@code localhost:5432}, and a test that fell back to them would write into them, or empty them. Without the
 * variables the test is skipped before it opens a connection, and the reason names what to set. Point the variables at
 * throwaway servers (CONTRIBUTING.md shows two containers).
 */
public final class TestStores {

    public static final String REDIS_HOST = "CONTEXA_TEST_REDIS_HOST";
    public static final String REDIS_PORT = "CONTEXA_TEST_REDIS_PORT";
    public static final String DB_URL = "CONTEXA_TEST_DB_URL";
    public static final String DB_USERNAME = "CONTEXA_TEST_DB_USERNAME";
    public static final String DB_PASSWORD = "CONTEXA_TEST_DB_PASSWORD";

    /** Where a developer's own Redis usually listens: a test that empties its Redis is never run against it. */
    static final int USUAL_DEVELOPER_REDIS_PORT = 6379;

    private static final String LOOPBACK = "127.0.0.1";

    private TestStores() {
    }

    /** A Redis named by {@code CONTEXA_TEST_REDIS_HOST} (the loopback address when unset) and its port. */
    public record Redis(String host, int port) {

        public String uri() {
            return "redis://" + host + ":" + port;
        }
    }

    /** A PostgreSQL database named by its JDBC URL; a user name or password left unset stays {@code null}. */
    public record Database(String url, String username, String password) {

        @Override
        public String toString() {
            return "Database[url=" + url + ", username=" + username + "]";
        }
    }

    /** The Redis of the test, which is skipped when {@code CONTEXA_TEST_REDIS_PORT} is not set. */
    public static Redis redis() {
        return redis(System::getenv);
    }

    /**
     * The Redis of a test that empties it (FLUSHDB, FLUSHALL, or every key it finds): skipped as {@link #redis()} is,
     * and failed, not skipped, when the port is 6379, whatever the host, because that is where a developer's own Redis
     * usually is.
     */
    public static Redis disposableRedis() {
        return disposableRedis(System::getenv);
    }

    /** The Redis when the variables name one, for a test that runs in memory too and adds Redis only when it is set. */
    public static Optional<Redis> findRedis() {
        return findRedis(System::getenv);
    }

    /** The database of the test, which is skipped when {@code CONTEXA_TEST_DB_URL} is not set. */
    public static Database database() {
        return database(System::getenv);
    }

    static Redis redis(Function<String, String> environment) {
        Optional<Redis> redis = findRedis(environment);
        if (redis.isEmpty()) {
            skip("this test needs a Redis of its own. Set " + REDIS_PORT + " and " + REDIS_HOST + " (" + LOOPBACK
                    + " when unset) to a throwaway Redis, never your own; without them the test connects nowhere.");
        }
        return redis.get();
    }

    static Redis disposableRedis(Function<String, String> environment) {
        Redis redis = redis(environment);
        if (redis.port() == USUAL_DEVELOPER_REDIS_PORT) {
            Assertions.fail(REDIS_PORT + " is " + USUAL_DEVELOPER_REDIS_PORT + ", where a developer's own Redis usually"
                    + " listens, and this test empties the Redis it uses (FLUSHDB). Start a throwaway Redis on another"
                    + " port and set " + REDIS_PORT + " to it.");
        }
        return redis;
    }

    static Optional<Redis> findRedis(Function<String, String> environment) {
        String port = value(environment, REDIS_PORT);
        if (port == null) {
            return Optional.empty();
        }
        if (!port.matches("[0-9]{1,5}")) {
            Assertions.fail(REDIS_PORT + " must be a port number, not '" + port + "'.");
        }
        String host = value(environment, REDIS_HOST);
        return Optional.of(new Redis(host == null ? LOOPBACK : host, Integer.parseInt(port)));
    }

    static Database database(Function<String, String> environment) {
        String url = value(environment, DB_URL);
        if (url == null) {
            skip("this test needs a PostgreSQL database of its own. Set " + DB_URL + " (with " + DB_USERNAME + " and "
                    + DB_PASSWORD + ") to a throwaway database, never your own; without it the test connects nowhere.");
        }
        return new Database(url, value(environment, DB_USERNAME), value(environment, DB_PASSWORD));
    }

    /**
     * Skips the test. The reason also goes to the error stream: Gradle's report keeps no reason for the tests of a class
     * skipped in {@code @BeforeAll}, only the output of the class.
     */
    private static void skip(String reason) {
        String message = "Skipped: " + reason;
        System.err.println("[TestStores] " + message);
        Assumptions.abort(message);
    }

    private static String value(Function<String, String> environment, String name) {
        String value = environment.apply(name);
        return value == null || value.isBlank() ? null : value.trim();
    }
}
