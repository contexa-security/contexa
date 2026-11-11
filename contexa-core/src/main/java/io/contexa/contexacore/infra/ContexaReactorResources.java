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
package io.contexa.contexacore.infra;

import io.netty.channel.EventLoopGroup;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ReactorClientHttpRequestFactoryBuilder;
import reactor.core.scheduler.NonBlocking;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;
import reactor.netty.resources.LoopResources;

import java.time.Duration;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The threads of Contexa's reactive work. A Reactor Netty client that is given no event loop runs on the JVM's global one
 * ({@code reactor-http-nio}), and it starts every thread of it, as many as cores, at its first connection or name lookup; a timeout,
 * a delay or a timed buffer of Reactor that is given no scheduler runs on its global {@code parallel} scheduler, also as many
 * threads as cores. Both belong to the whole JVM: an application's own WebClient and reactive code share them, so a model call
 * that waits for minutes held the threads the application's calls run on, and an application that has neither got both pools when
 * Contexa was mounted. Contexa's HTTP clients run on an event loop of its own and its timers on a scheduler of its own, each of a
 * few daemon threads, started at the first use.
 * <p>
 * How many: what runs on the event loop is the moving of bytes of Contexa's calls (the decoding of a call's answer runs on the
 * thread that made the call), and the calls at once are bounded by the gate of each model server (2 on a self-hosted server, 16 on
 * a remote provider, by default); a thread of an event loop serves thousands of connections, and the second keeps the calls moving
 * while the first is busy with a name lookup or a TLS handshake. What runs on the timer is starting and cancelling the time limit of
 * a call, a microsecond's work, and the flush of a stream's timed buffer.
 * <p>
 * Each application context that mounts Contexa holds them ({@link #hold()}). When the last one closes, the threads end; a later use
 * starts new ones. A thread of either starts with its first task, so an application whose Contexa makes no call has none.
 */
@Slf4j
public final class ContexaReactorResources {

    static final int EVENT_LOOP_THREADS = 2;
    static final int TIMER_THREADS = 2;
    static final String EVENT_LOOP_PREFIX = "contexa-ai";
    static final String TIMER_NAME = "contexa-timer";
    private static final Duration SHUTDOWN_TIMEOUT = Duration.ofSeconds(5);

    private static final Object LOCK = new Object();
    private static volatile Resources current;
    private static int holders;

    private ContexaReactorResources() {
    }

    /** The scheduler of the time limits, delays and timed buffers of Contexa's reactive calls. */
    public static Scheduler timer() {
        return resources().timer;
    }

    /** The event loops of Contexa's HTTP clients. */
    public static LoopResources eventLoops() {
        return resources().loops;
    }

    /** The client on Contexa's event loops: its connections, and its name lookups unless it was given a resolver of its own. */
    public static HttpClient onContexaLoops(HttpClient client) {
        return client.runOn(eventLoops());
    }

    /**
     * The builder of request factories with its Reactor Netty client on Contexa's event loops, and every other setting as the
     * builder has it; a builder of another client, which has no event loop, as it is.
     */
    public static ClientHttpRequestFactoryBuilder<?> onContexaLoops(ClientHttpRequestFactoryBuilder<?> builder) {
        return builder instanceof ReactorClientHttpRequestFactoryBuilder reactor
                ? reactor.withHttpClientCustomizer(ContexaReactorResources::onContexaLoops)
                : builder;
    }

    /**
     * A pool of connections as {@code ConnectionProvider.create(name, maxConnections)} makes it, with the timer of a request that
     * waits for a connection on Contexa's timer instead of Reactor's {@code parallel} scheduler.
     */
    public static ConnectionProvider connections(String name, int maxConnections) {
        return ConnectionProvider.builder(name)
                .maxConnections(maxConnections)
                .pendingAcquireTimeout(Duration.ofMillis(ConnectionProvider.DEFAULT_POOL_ACQUIRE_TIMEOUT))
                .pendingAcquireTimer((task, delay) -> timer().schedule(task, delay.toMillis(), TimeUnit.MILLISECONDS))
                .build();
    }

    /** Taken by each application context that mounts Contexa, and closed with it. */
    public static Hold hold() {
        synchronized (LOCK) {
            holders++;
        }
        return new Hold();
    }

    private static Resources resources() {
        Resources resources = current;
        if (resources != null) {
            return resources;
        }
        synchronized (LOCK) {
            if (current == null) {
                current = new Resources();
            }
            return current;
        }
    }

    private static void release() {
        Resources ending;
        synchronized (LOCK) {
            holders = Math.max(0, holders - 1);
            if (holders > 0 || current == null) {
                return;
            }
            ending = current;
            current = null;
        }
        ending.dispose();
    }

    /**
     * The threads of the timer: daemons, numbered on their own (a scheduler made with {@code newParallel(name, ...)} draws its
     * numbers from Reactor's counter of {@code parallel} threads, and the application's would then be numbered after Contexa's),
     * and marked non-blocking as Reactor's parallel threads are, so that a {@code block()} after a time limit fails as it did.
     */
    private static final class TimerThreads implements ThreadFactory {

        private final AtomicLong number = new AtomicLong();

        @Override
        public Thread newThread(Runnable task) {
            Thread thread = new TimerThread(task, TIMER_NAME + "-" + number.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }

    private static final class TimerThread extends Thread implements NonBlocking {

        private TimerThread(Runnable task, String name) {
            super(task, name);
        }
    }

    /** One application context's hold on the threads. */
    public static final class Hold implements AutoCloseable {

        private final AtomicBoolean released = new AtomicBoolean();

        private Hold() {
        }

        @Override
        public void close() {
            if (released.compareAndSet(false, true)) {
                release();
            }
        }
    }

    /**
     * Created without a thread: a loop of the event loop and a worker of the timer start their thread with their first task. The
     * loops are not colocated: a colocated group hands every loop a task when it is made, which starts all their threads at the
     * first client that is built, and Contexa's calls never start on a loop of their own anyway.
     */
    private static final class Resources {

        private final LoopResources loops = LoopResources.create(EVENT_LOOP_PREFIX, -1, EVENT_LOOP_THREADS, true, false);
        private final Scheduler timer = Schedulers.newParallel(TIMER_THREADS, new TimerThreads());

        /**
         * The timer ends at once; the loops end through Netty, because {@code LoopResources.disposeLater} measures its own limit
         * on Reactor's parallel scheduler. Every client of Contexa runs on the client loops of the default transport.
         */
        private void dispose() {
            timer.dispose();
            EventLoopGroup group = loops.onClient(LoopResources.DEFAULT_NATIVE);
            boolean ended = group.shutdownGracefully(0L, SHUTDOWN_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
                    .awaitUninterruptibly(SHUTDOWN_TIMEOUT.plusSeconds(1).toMillis());
            if (!ended) {
                log.error("[Contexa] The event loop of Contexa's HTTP clients did not end within {}", SHUTDOWN_TIMEOUT);
            }
        }
    }
}
