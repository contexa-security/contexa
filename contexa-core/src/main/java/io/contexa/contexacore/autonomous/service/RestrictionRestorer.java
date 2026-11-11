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
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.SmartLifecycle;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;
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
 * <p>
 * A store that is not the memory of the server can lose its blocks while the application runs: a Redis that is emptied,
 * restarted without its data or replaced loses every BLOCK flag at once, and the user is let through until a model decides
 * on the user again. So where the store lives outside the server the blocks in force are looked at again, on the
 * restorer's own thread: every {@value #LOOK_AGAIN_SECONDS} seconds, and at once when Redis answers again after an outage
 * the requests met. A look writes what is absent and nothing else, as a try does, so it may run on every server and meanwhile
 * a try; it never reads the database or Redis on the thread of a request. A block that an administrator released while a
 * look was writing it is taken out again, because the record is resolved before the store is cleared (see
 * {@link #withdrawReleased}). Decisions that are not enforced (SHADOW, OBSERVE, DISABLED) stop nothing, so nothing is
 * looked at then. A CHALLENGE and a learning quarantine have no record and are not written by a look.
 */
@Slf4j
public class RestrictionRestorer implements SmartLifecycle {

    /** Before the web server starts: Spring Boot's server lifecycle runs at {@code Integer.MAX_VALUE - 2048}. */
    public static final int PHASE = SmartLifecycle.DEFAULT_PHASE - 4096;

    /** How long the start waits for the first try before it goes on and leaves the rest to the background. */
    static final Duration FIRST_ATTEMPT_WAIT = Duration.ofSeconds(15);

    /** The waits before each further try: six tries over about four minutes. */
    static final List<Duration> RETRY_DELAYS = List.of(Duration.ofSeconds(5), Duration.ofSeconds(15),
            Duration.ofSeconds(30), Duration.ofSeconds(60), Duration.ofSeconds(120));

    /**
     * How long a block the store lost stays out of it, at most, when nothing told the application that the store was
     * lost: one wait between two looks. A look is one statement on the record and one command to Redis for each block in
     * force (and nothing at all while the decisions are not enforced or a store is down), so a quarter of a minute costs
     * a few commands a second where hundreds of blocks are in force and leaves a blocked user at most that long unblocked.
     * A block is looked at in the next look after it was recorded; the wait is also the time one server leaves another to
     * write the flags, as only the first write counts.
     */
    static final int LOOK_AGAIN_SECONDS = 15;

    static final Duration LOOK_AGAIN_AFTER = Duration.ofSeconds(LOOK_AGAIN_SECONDS);

    /**
     * A look may take no more than one part in this many of the restorer's time: after a look that took long (a long list
     * of blocks, a slow database) the wait is that many times as long as the look took, when that is more than the wait.
     */
    static final int BUSY_SHARE = 20;

    /** While a store stays down a look that fails is reported again only after this many looks in a row failed. */
    private static final int REPORT_AGAIN_AFTER_FAILED_LOOKS = 40;

    private static final String THREAD = "contexa-restriction-restorer";

    private final Supplier<ZeroTrustActionRepository> actions;
    private final Supplier<IBlockedUserRecorder> recorder;
    private final Supplier<SecurityContextDataStore> contextStore;
    private final Duration firstAttemptWait;
    private final List<Duration> retryDelays;
    private final Duration lookAgainAfter;
    /** The blocks this server wrote that no look has confirmed, by the record of that moment, to be in force still. */
    private final Set<String> unconfirmed = ConcurrentHashMap.newKeySet();

    private volatile boolean running;
    private volatile ScheduledThreadPoolExecutor executor;
    private volatile BooleanSupplier enforcing = () -> true;
    private volatile ContexaStores stores;
    /** Whether the store can lose a block while the application runs, which is known once the application has started. */
    private volatile boolean looking;
    /** The first tries have ended, in a write or in giving up: until then they are the ones that report what goes wrong. */
    private volatile boolean startSettled;
    /** The looks in a row that failed; read and written by the restorer's thread only. */
    private int failedLooks;

    /** The parts are asked for when the try is made: they all exist by the time the lifecycle starts. */
    public RestrictionRestorer(Supplier<ZeroTrustActionRepository> actions,
                                        Supplier<IBlockedUserRecorder> recorder,
                                        Supplier<SecurityContextDataStore> contextStore) {
        this(actions, recorder, contextStore, FIRST_ATTEMPT_WAIT, RETRY_DELAYS);
    }

    RestrictionRestorer(Supplier<ZeroTrustActionRepository> actions, Supplier<IBlockedUserRecorder> recorder,
                                 Supplier<SecurityContextDataStore> contextStore, Duration firstAttemptWait,
                                 List<Duration> retryDelays) {
        this(actions, recorder, contextStore, firstAttemptWait, retryDelays, LOOK_AGAIN_AFTER);
    }

    RestrictionRestorer(Supplier<ZeroTrustActionRepository> actions, Supplier<IBlockedUserRecorder> recorder,
                                 Supplier<SecurityContextDataStore> contextStore, Duration firstAttemptWait,
                                 List<Duration> retryDelays, Duration lookAgainAfter) {
        this.actions = actions;
        this.recorder = recorder;
        this.contextStore = contextStore;
        this.firstAttemptWait = firstAttemptWait;
        this.retryDelays = List.copyOf(retryDelays);
        this.lookAgainAfter = lookAgainAfter;
    }

    /**
     * Whether decisions are enforced. Under SHADOW, OBSERVE or DISABLED a BLOCK flag stops nothing, so the looks that
     * follow the start are not made then; the start itself writes the blocks whatever the mode, as it always did.
     */
    public void setEnforcing(BooleanSupplier enforcing) {
        this.enforcing = enforcing != null ? enforcing : () -> true;
    }

    /**
     * The stores as the requests see them. A look is not made while Redis or the database is known to be down, and one is
     * made at once when Redis answers again, which is the moment a Redis that came back empty can be written to.
     */
    public void setContexaStores(ContexaStores stores) {
        this.stores = stores;
        stores.redis().whenBack(this::redisAnswersAgain);
    }

    @Override
    public void start() {
        if (running) {
            return;
        }
        running = true;
        startSettled = false;
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
        looking = storeCanLoseBlocks();
        if (looking) {
            scheduleLook(lookAgainAfter);
        }
    }

    @Override
    public void stop() {
        running = false;
        looking = false;
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

    /**
     * Only a store outside the server can lose a block while the server runs: the memory of the server ends with it, and the
     * start has written the blocks into it. Without a record of blocks there is nothing to look at.
     */
    private boolean storeCanLoseBlocks() {
        ZeroTrustActionRepository repository = actions.get();
        return repository != null && !(repository instanceof InMemoryZeroTrustActionRepository) && recorder.get() != null;
    }

    private void attempt(int attempt) {
        try {
            bringOver();
            startSettled = true;
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

        try {
            Restored restored = restoreBlocks();
            inForce = restored.inForce();
            written = restored.written();
        } catch (RuntimeException failed) {
            if (failure == null) {
                failure = failed;
            } else {
                failure.addSuppressed(failed);
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

    /** What one pass over the record found: the blocks in force, and the ones of them the store did not hold. */
    private record Restored(int inForce, int written) {
    }

    /** Writes each block the record holds in force where the store has none. */
    private Restored restoreBlocks() {
        ZeroTrustActionRepository repository = actions.get();
        IBlockedUserRecorder record = recorder.get();
        if (repository == null || record == null) {
            return new Restored(0, 0);
        }
        RuntimeException failure = null;
        int inForce = 0;
        int written = 0;
        try {
            List<String> blocks = record.blocksInForce();
            inForce = blocks.size();
            for (String userId : blocks) {
                if (repository.restoreBlockedFlag(userId)) {
                    unconfirmed.add(userId);
                    written++;
                }
            }
        } catch (RuntimeException failed) {
            failure = failed;
        }
        try {
            withdrawReleased(repository, record);
        } catch (RuntimeException failed) {
            if (failure == null) {
                failure = failed;
            } else {
                failure.addSuppressed(failed);
            }
        }
        if (failure != null) {
            throw failure;
        }
        return new Restored(inForce, written);
    }

    /**
     * An administrator's release resolves the record in the database and, once that is committed, clears the BLOCK flag. A
     * write that read the record before the release and reached the store after the flag was cleared would put the block
     * back for good: the record no longer holds it, so no later try would take it away. So each block written here is
     * asked after the write whether the record still holds it in force, and taken out again when it does not. Read in this
     * order the answer is never wrong for long: a release committed before the question is seen by it, and one committed
     * after it clears the flag after this write, as the flag is cleared only after the commit. The question is asked of
     * the list the record gives, which is the list the writes came from, in one statement for all the blocks written.
     */
    private void withdrawReleased(ZeroTrustActionRepository repository, IBlockedUserRecorder record) {
        if (unconfirmed.isEmpty()) {
            return;
        }
        Set<String> inForce = new HashSet<>(record.blocksInForce());
        for (String userId : List.copyOf(unconfirmed)) {
            if (!inForce.contains(userId)) {
                repository.removeBlockedFlag(userId);
            }
            unconfirmed.remove(userId);
        }
    }

    private void retryOrGiveUp(int attempt, RuntimeException failure) {
        int attempts = retryDelays.size() + 1;
        if (attempt >= attempts) {
            startSettled = true;
            log.error("[RestrictionRestorer] Restrictions could not be restored: gave up after {} tries, so a block the "
                    + "database holds in force, or a quarantine, may not be in force until the next start{}", attempts,
                    looking ? " or, for a block, until the next look" : "", failure);
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

    // ----- the looks while the application runs -----

    private void scheduleLook(Duration wait) {
        ScheduledThreadPoolExecutor own = executor;
        if (!running || own == null) {
            return;
        }
        try {
            own.schedule(this::lookAndLookAgain, wait.toMillis(), TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException stopped) {
            log.debug("[RestrictionRestorer] Stopped before the next look");
        }
    }

    private void lookAndLookAgain() {
        long began = System.nanoTime();
        boolean worked = false;
        try {
            worked = look();
        } finally {
            // Only a look that did its work is a load to leave room after; one that waited for a store that is down is not.
            Duration took = Duration.ofNanos(System.nanoTime() - began);
            scheduleLook(worked && took.multipliedBy(BUSY_SHARE).compareTo(lookAgainAfter) > 0
                    ? took.multipliedBy(BUSY_SHARE) : lookAgainAfter);
        }
    }

    /** Redis answers again: what it lost while it was away can be written now. The gate's thread hands the work over. */
    private void redisAnswersAgain() {
        ScheduledThreadPoolExecutor own = executor;
        if (!running || !looking || own == null) {
            return;
        }
        try {
            own.execute(() -> look());
        } catch (RejectedExecutionException stopped) {
            log.debug("[RestrictionRestorer] Stopped before the look");
        }
    }

    /**
     * One look. It never throws: what goes wrong is reported and tried again at the next look.
     *
     * @return whether the look read the record and wrote what was absent
     */
    private boolean look() {
        if (!running || !startSettled || !worthLooking()) {
            return false;
        }
        try {
            Restored restored = restoreBlocks();
            failedLooks = 0;
            if (restored.written() > 0) {
                log.info("[RestrictionRestorer] Blocks the store lost were written again from the record: {} of {} blocks in "
                        + "force", restored.written(), restored.inForce());
            }
            return true;
        } catch (RuntimeException failure) {
            failedLooks++;
            if (failedLooks == 1 || failedLooks % REPORT_AGAIN_AFTER_FAILED_LOOKS == 0) {
                log.error("[RestrictionRestorer] The blocks in force could not be looked at again ({} looks in a row failed), "
                        + "so a block the store lost is not written back until one succeeds: {}", failedLooks,
                        describe(failure));
            }
            return false;
        }
    }

    /** A look can do something only where decisions are enforced and no store is known to be down: Redis is looked for by its gate. */
    private boolean worthLooking() {
        if (!enforcing.getAsBoolean()) {
            return false;
        }
        ContexaStores known = stores;
        return known == null || !known.anyDown();
    }

    private static String describe(Throwable failure) {
        Throwable cause = failure;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        return failure.getMessage() + (cause != failure ? " (" + cause.getMessage() + ")" : "");
    }
}
