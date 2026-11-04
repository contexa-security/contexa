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
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Asks Contexa's own database whether it answers, before anything of Contexa is created. A database that is still coming up
 * is waited for within a short window, and an attempt runs on a daemon thread of its own: a database that never answers
 * costs the application the window, and the JVM-wide login timeout of {@link DriverManager} stays the application's.
 */
class ContexaDatabaseProbe {

    private static final Duration DEFAULT_WINDOW = Duration.ofSeconds(5);
    private static final Duration DEFAULT_PAUSE = Duration.ofSeconds(1);
    private static final String NO_ANSWER = "no answer in time";

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
        try {
            url = environment.getProperty("contexa.datasource.url");
            username = environment.getProperty("contexa.datasource.username");
            password = environment.getProperty("contexa.datasource.password");
        } catch (IllegalArgumentException unresolvedPlaceholder) {
            return null;
        }
        if (url == null || url.isBlank() || !readable(url)) {
            return null;
        }
        long deadline = System.nanoTime() + window.toNanos();
        String problem = null;
        do {
            String attempt = attempt(url, username, password, deadline);
            if (attempt == null) {
                return null;
            }
            // the window running out during an attempt says nothing; what the database last answered is the reason
            if (problem == null || !NO_ANSWER.equals(attempt)) {
                problem = attempt;
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

    @Nullable
    private static String attempt(String url, @Nullable String username, @Nullable String password, long deadline) {
        FutureTask<Boolean> connecting = new FutureTask<>(() -> {
            try (Connection ignored = DriverManager.getConnection(url, username, password)) {
                return true;
            }
        });
        Thread thread = new Thread(connecting, "contexa-database-probe");
        thread.setDaemon(true);
        thread.start();
        try {
            connecting.get(Math.max(1L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            return null;
        } catch (TimeoutException noAnswer) {
            return NO_ANSWER;
        } catch (ExecutionException refused) {
            return String.valueOf(refused.getCause().getMessage());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return "interrupted";
        }
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
