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

import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * One store as the requests see it. One request that meets the outage pays for it, about a second; from then on the
 * gate is down and a request does not wait at all. A thread of its own, which lives only as long as the outage, looks for
 * the store and raises the gate as soon as the store answers, so the store coming back needs no action and no request
 * pays for finding out.
 */
@Slf4j
public final class StoreGate {

    /** A look at the store; a look that throws found it down. */
    @FunctionalInterface
    public interface Probe {
        void check() throws Exception;
    }

    private static final long UP = 0L;
    private static final Duration PROBE_INTERVAL = Duration.ofSeconds(1);
    private static final Duration REPORT_INTERVAL = Duration.ofMinutes(1);

    private final String name;
    private final long probeIntervalMillis;
    private final Runnable whenBack;
    private final AtomicLong downSince = new AtomicLong(UP);
    private volatile Probe probe;
    private volatile Thread watcher;

    StoreGate(String name, Runnable whenBack) {
        this(name, whenBack, PROBE_INTERVAL);
    }

    StoreGate(String name, Runnable whenBack, Duration probeInterval) {
        this.name = name;
        this.whenBack = whenBack;
        this.probeIntervalMillis = probeInterval.toMillis();
    }

    public String name() {
        return name;
    }

    /** How the gate looks for the store. Without a probe the gate stays up: nothing could raise it again. */
    public void watchWith(Probe probe) {
        this.probe = probe;
    }

    public boolean isDown() {
        return downSince.get() != UP;
    }

    /** What a request meets instead of a wait. */
    public StoreUnavailableException unavailable() {
        return new StoreUnavailableException(name);
    }

    /** Takes in a failure of the store; any other failure is left for its caller. */
    public void fail(Throwable failure) {
        if (probe == null || !StoreFailures.isStoreFailure(failure) || StoreFailures.isReportedOutage(failure)) {
            return;
        }
        if (downSince.compareAndSet(UP, System.currentTimeMillis())) {
            log.error("[Contexa] {} does not answer ({}): the application's requests go on without waiting for it, and a "
                    + "protected call goes on without a decision until it is back.", name, describe(failure));
            startWatching();
        }
    }

    private static String describe(Throwable failure) {
        Throwable root = failure;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        return root.getClass().getSimpleName() + ": " + root.getMessage();
    }

    private void startWatching() {
        Thread thread = new Thread(this::watch, "contexa-store-watch");
        thread.setDaemon(true);
        watcher = thread;
        thread.start();
    }

    private void watch() {
        long reportAt = System.currentTimeMillis() + REPORT_INTERVAL.toMillis();
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Thread.sleep(probeIntervalMillis);
                if (answers()) {
                    raise();
                    return;
                }
                long now = System.currentTimeMillis();
                if (now >= reportAt) {
                    reportAt = now + REPORT_INTERVAL.toMillis();
                    log.error("[Contexa] {} has not answered for {} seconds; the application's requests go on without it.",
                            name, Duration.ofMillis(now - downSince.get()).toSeconds());
                }
            } catch (InterruptedException stopped) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private boolean answers() {
        try {
            probe.check();
            return true;
        } catch (Exception stillDown) {
            return false;
        }
    }

    private void raise() {
        long since = downSince.getAndSet(UP);
        log.warn("[Contexa] {} answers again after {} seconds; requests read it again.", name,
                Duration.ofMillis(System.currentTimeMillis() - since).toSeconds());
        whenBack.run();
    }

    void stop() {
        Thread thread = watcher;
        if (thread != null) {
            thread.interrupt();
        }
    }
}
