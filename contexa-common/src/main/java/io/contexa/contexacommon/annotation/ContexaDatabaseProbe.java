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

import org.springframework.core.env.Environment;
import org.springframework.lang.Nullable;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Asks Contexa's own database whether it answers, before anything of Contexa is created. A database that is still coming up
 * is waited for within a short window, and an attempt runs on a daemon thread of its own: a database that never answers
 * costs the application the window, and the JVM-wide login timeout of {@link DriverManager} stays the application's.
 * <p>
 * A database that answers can still stop the start: its account may not be allowed to create the extensions Contexa's
 * start creates, which only an administrator can do on most servers. That is asked here as well, once the database
 * answers, by creating them and taking that back. What an account may create depends on the server, on the extension and
 * on what was granted, and the start would run the same statements a moment later.
 */
class ContexaDatabaseProbe {

    private static final Duration DEFAULT_WINDOW = Duration.ofSeconds(5);
    private static final Duration DEFAULT_PAUSE = Duration.ofSeconds(1);
    private static final String NO_ANSWER = "no answer in time";
    private static final String POSTGRESQL = "PostgreSQL";
    private static final String VECTOR_STORE_INITIALIZES_SCHEMA = "contexa.vectorstore.pgvector.initialize-schema";
    /** What the schema script creates. */
    private static final String SCHEMA_EXTENSION = "vector";
    /** What Spring AI's vector store creates as well when it makes its table. */
    private static final List<String> VECTOR_STORE_EXTENSIONS = List.of("hstore", "uuid-ossp");

    private final Duration window;
    private final Duration pause;

    ContexaDatabaseProbe() {
        this(DEFAULT_WINDOW, DEFAULT_PAUSE);
    }

    ContexaDatabaseProbe(Duration window, Duration pause) {
        this.window = window;
        this.pause = pause;
    }

    /** Why the database cannot be used, or null when it answers or when there is nothing this probe can ask. */
    @Nullable
    String problem(Environment environment) {
        String url;
        String username;
        String password;
        List<String> extensions;
        try {
            url = environment.getProperty("contexa.datasource.url");
            username = environment.getProperty("contexa.datasource.username");
            password = environment.getProperty("contexa.datasource.password");
            extensions = extensions(environment);
        } catch (IllegalArgumentException unresolvedPlaceholder) {
            return null;
        }
        if (url == null || url.isBlank() || !readable(url)) {
            return null;
        }
        long deadline = System.nanoTime() + window.toNanos();
        String problem = null;
        do {
            Attempt attempt = attempt(url, username, password, extensions, deadline);
            if (attempt.answered()) {
                return attempt.problem();
            }
            // the window running out during an attempt says nothing; what the database last answered is the reason
            if (problem == null || !NO_ANSWER.equals(attempt.problem())) {
                problem = attempt.problem();
            }
            if (!pause()) {
                break;
            }
        } while (System.nanoTime() < deadline);
        return problem;
    }

    private static boolean readable(String url) {
        try {
            return DriverManager.getDriver(url) != null;
        } catch (SQLException noDriver) {
            return false;
        }
    }

    private static List<String> extensions(Environment environment) {
        List<String> extensions = new ArrayList<>(List.of(SCHEMA_EXTENSION));
        if (!"false".equalsIgnoreCase(environment.getProperty(VECTOR_STORE_INITIALIZES_SCHEMA))) {
            extensions.addAll(VECTOR_STORE_EXTENSIONS);
        }
        return extensions;
    }

    private static Attempt attempt(String url, @Nullable String username, @Nullable String password,
                                   List<String> extensions, long deadline) {
        FutureTask<String> connecting = new FutureTask<>(() -> {
            try (Connection connection = DriverManager.getConnection(url, username, password)) {
                return extensionProblem(connection, extensions);
            }
        });
        Thread thread = new Thread(connecting, "contexa-database-probe");
        thread.setDaemon(true);
        thread.start();
        try {
            return new Attempt(connecting.get(Math.max(1L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS), true);
        } catch (TimeoutException noAnswer) {
            return new Attempt(NO_ANSWER, false);
        } catch (ExecutionException refused) {
            return new Attempt(String.valueOf(refused.getCause().getMessage()), false);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return new Attempt("interrupted", false);
        }
    }

    /** Why the account cannot make what the start needs, or null. Nothing of the attempt stays in the database. */
    @Nullable
    private static String extensionProblem(Connection connection, List<String> extensions) throws SQLException {
        DatabaseMetaData metadata = connection.getMetaData();
        if (metadata == null || !POSTGRESQL.equals(metadata.getDatabaseProductName())) {
            return null;
        }
        connection.setAutoCommit(false);
        try (Statement statement = connection.createStatement()) {
            for (String extension : extensions) {
                try {
                    statement.execute("create extension if not exists \"" + extension + "\"");
                } catch (SQLException refused) {
                    // the driver adds the server's hint on lines of their own; the start says this in one line
                    return String.valueOf(refused.getMessage()).lines().findFirst().orElse("refused")
                            + "; an administrator of the database runs CREATE EXTENSION \"" + extension + "\" in it";
                }
            }
            return null;
        } finally {
            connection.rollback();
        }
    }

    /** What an attempt came to; a database that answered says the same again, so there is no reason to ask it twice. */
    private record Attempt(@Nullable String problem, boolean answered) {
    }

    private boolean pause() {
        try {
            Thread.sleep(pause.toMillis());
            return true;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
