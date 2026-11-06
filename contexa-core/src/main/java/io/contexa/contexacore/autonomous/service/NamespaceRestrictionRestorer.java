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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.SmartLifecycle;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

/**
 * Writes again the restrictions that have no expiry and that the decision store may have lost. A BLOCK and a learning
 * quarantine are kept until someone lifts them, and a restart can take them: in standalone the store is the memory of
 * the server; in distributed mode a Redis that was emptied or replaced, or the keys an application had before it was
 * given a name, which are no longer read (they may be another application's). The database holds the blocks in force
 * ({@link IBlockedUserRecorder#blocksInForce}), the second copy of every BLOCK, and they are written again as the BLOCK
 * flags of the store, where there is none, in every mode and with or without a name. The quarantine has no such record: it
 * is carried only from the earlier key of an application that was given a name
 * ({@link SecurityContextDataStore#carryOverLearningQuarantine}), and not at all in standalone, where it ends with the
 * memory.
 * <p>
 * It runs when the application starts, before the web server takes a request (Spring Boot starts the server in a lifecycle
 * at {@code Integer.MAX_VALUE - 2048}). What goes wrong never stops the application and never holds a request: the first
 * try is given a short time, then it goes on in the background; an error is reported at ERROR and tried again a number of
 * times, and said once more when the last try fails. A try writes only what is absent, so it can be repeated. Without a
 * record of blocks (no contexa-iam) there is nothing to write.
 */
@Slf4j
public class NamespaceRestrictionRestorer implements SmartLifecycle {

    /** Before the web server starts: Spring Boot's server lifecycle runs at {@code Integer.MAX_VALUE - 2048}. */
    public static final int PHASE = SmartLifecycle.DEFAULT_PHASE - 4096;

    /** How long the start waits for the first try before it goes on and leaves the rest to the background. */
    static final Duration FIRST_ATTEMPT_WAIT = Duration.ofSeconds(15);

    /** The waits before each further try: six tries over about four minutes. */
    static final List<Duration> RETRY_DELAYS = List.of(Duration.ofSeconds(5), Duration.ofSeconds(15),
            Duration.ofSeconds(30), Duration.ofSeconds(60), Duration.ofSeconds(120));

    private static final String THREAD = "contexa-restriction-restorer";

    private final Supplier<ZeroTrustActionRepository> actions;
    private final Supplier<IBlockedUserRecorder> recorder;
    private final Supplier<SecurityContextDataStore> contextStore;
    private final Duration firstAttemptWait;
    private final List<Duration> retryDelays;

    private volatile boolean running;
    private volatile ScheduledThreadPoolExecutor executor;

    /** The parts are asked for when the try is made: they all exist by the time the lifecycle starts. */
    public NamespaceRestrictionRestorer(Supplier<ZeroTrustActionRepository> actions,
                                        Supplier<IBlockedUserRecorder> recorder,
                                        Supplier<SecurityContextDataStore> contextStore) {
        this(actions, recorder, contextStore, FIRST_ATTEMPT_WAIT, RETRY_DELAYS);
    }

    NamespaceRestrictionRestorer(Supplier<ZeroTrustActionRepository> actions, Supplier<IBlockedUserRecorder> recorder,
                                 Supplier<SecurityContextDataStore> contextStore, Duration firstAttemptWait,
                                 List<Duration> retryDelays) {
        this.actions = actions;
        this.recorder = recorder;
        this.contextStore = contextStore;
        this.firstAttemptWait = firstAttemptWait;
        this.retryDelays = List.copyOf(retryDelays);
    }

    @Override
    public void start() {
        if (running) {
            return;
        }
        running = true;
        ScheduledThreadPoolExecutor own = new ScheduledThreadPoolExecutor(1, task -> {
            Thread thread = new Thread(task, THREAD);
            thread.setDaemon(true);
            return thread;
        });
        own.setRemoveOnCancelPolicy(true);
        executor = own;
        Future<?> first = own.submit(() -> attempt(1));
        try {
            first.get(firstAttemptWait.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException slow) {
            log.warn("[RestrictionRestorer] The first try did not end within {}: the application goes on starting and the "
                    + "blocks in force are written again in the background", firstAttemptWait);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (ExecutionException unexpected) {
            log.error("[RestrictionRestorer] The restrictions could not be restored", unexpected.getCause());
        }
    }

    @Override
    public void stop() {
        running = false;
        ScheduledThreadPoolExecutor own = executor;
        if (own != null) {
            own.shutdownNow();
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public int getPhase() {
        return PHASE;
    }

    private void attempt(int attempt) {
        try {
            bringOver();
        } catch (RuntimeException failure) {
            retryOrGiveUp(attempt, failure);
        }
    }

    /** Both parts are tried whatever the other does, and the first failure is the one reported. */
    private void bringOver() {
        RuntimeException failure = null;
        int carried = 0;
        int written = 0;
        int inForce = 0;

        // Only an application with a name has earlier keys to carry the quarantine from.
        SecurityContextDataStore store = ApplicationNamespace.isNamed() ? contextStore.get() : null;
        if (store != null) {
            try {
                carried = store.carryOverLearningQuarantine();
            } catch (RuntimeException failed) {
                failure = failed;
            }
        }

        ZeroTrustActionRepository repository = actions.get();
        IBlockedUserRecorder record = recorder.get();
        if (repository != null && record != null) {
            try {
                List<String> blocks = record.blocksInForce();
                inForce = blocks.size();
                for (String userId : blocks) {
                    if (repository.restoreBlockedFlag(userId)) {
                        written++;
                    }
                }
            } catch (RuntimeException failed) {
                if (failure == null) {
                    failure = failed;
                } else {
                    failure.addSuppressed(failed);
                }
            }
        }

        if (failure != null) {
            throw failure;
        }
        if (carried > 0 || written > 0) {
            log.info("[RestrictionRestorer] Restrictions without an expiry were restored: {} of {} blocks in force written "
                    + "again, {} quarantined scopes carried over", written, inForce, carried);
        }
    }

    private void retryOrGiveUp(int attempt, RuntimeException failure) {
        int attempts = retryDelays.size() + 1;
        if (attempt >= attempts) {
            log.error("[RestrictionRestorer] Restrictions could not be restored: gave up after {} tries, so a block the "
                    + "database holds in force, or a quarantine, may not be in force until the next start", attempts, failure);
            return;
        }
        Duration delay = retryDelays.get(attempt - 1);
        log.error("[RestrictionRestorer] Restrictions could not be restored (try {} of {}), again in {}: {}",
                attempt, attempts, delay, describe(failure));
        ScheduledThreadPoolExecutor own = executor;
        if (!running || own == null) {
            return;
        }
        try {
            own.schedule(() -> attempt(attempt + 1), delay.toMillis(), TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException stopped) {
            log.debug("[RestrictionRestorer] Stopped before the next try");
        }
    }

    private static String describe(Throwable failure) {
        Throwable cause = failure;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        return failure.getMessage() + (cause != failure ? " (" + cause.getMessage() + ")" : "");
    }
}
