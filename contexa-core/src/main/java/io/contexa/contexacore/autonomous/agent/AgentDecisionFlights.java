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
package io.contexa.contexacore.autonomous.agent;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * An agent's requests that come in numbers are not each analysed (docs/agent RL-12). A request that no stored
 * restriction and no ALLOW anchor answers asks the engine's model one question; the same question asked by many
 * requests at once is asked once. The first request of a kind leads: it is analysed. The others of that kind follow:
 * they wait for the leader's verdict and are answered by it, if what it allowed covers them, and by the restriction
 * in force otherwise. A follower the verdict does not cover leads the next flight.
 * <p>
 * Four rules keep this from becoming a way round the engine's decisions:
 * <ul>
 *   <li>No request is answered before a verdict because a verdict is pending. A request waits, or is told the engine is
 *   busy; it is never let through for lack of an answer. The one exception is {@link #tryPass}: a few requests for a
 *   resource the host declared non-sensitive, of a read-like kind, pass while the first one is decided, up to a budget.</li>
 *   <li>At most {@code maxInFlightAnalyses} analyses run for one subject whatever the contexts it works in. The
 *   requests that cannot start wait in a queue of {@code queueCapacity} for at most {@code wait}; past that they are
 *   busy.</li>
 *   <li>A restriction stored for the subject (BLOCK, ESCALATE, CHALLENGE) is read again right before any request is
 *   released and answers the waiting ones the moment it is stored: the restriction is the answer of a request whose own
 *   verdict is ALLOW (the final gate).</li>
 *   <li>A failure of the flights themselves is not a decision: the request is analysed on its own, as it was before.</li>
 * </ul>
 * The flights keep their own state in memory; several nodes need a shared registry.
 */
@Slf4j
public final class AgentDecisionFlights {

    /** How often a follower reads the stored state while it waits. */
    private static final long POLL_MILLIS = 25L;
    /** How long passes count as waiting for a verdict that never lands. */
    private static final long PASS_WINDOW_MILLIS = 60_000L;
    private static final int IDLE_SUBJECTS_KEPT = 10_000;

    /**
     * @param enabled              off, every request is analysed on its own as before
     * @param maxInFlightAnalyses  the analyses one subject may have running at once
     * @param queueCapacity        the requests of one subject that may wait for a place to analyse
     * @param maxWait              the longest a request waits for a place or for the verdict it follows
     * @param passBudget           the requests that may pass before the first verdict, 0 for none
     * @param passFamilies         the kinds of operation that may pass
     */
    public record Settings(boolean enabled, int maxInFlightAnalyses, int queueCapacity, Duration maxWait, int passBudget,
                           Set<ActionFamily> passFamilies) {

        public Settings {
            maxInFlightAnalyses = Math.max(1, maxInFlightAnalyses);
            queueCapacity = Math.max(0, queueCapacity);
            maxWait = maxWait == null || maxWait.isNegative() ? Duration.ZERO : maxWait;
            passBudget = Math.max(0, passBudget);
            passFamilies = passFamilies == null ? Set.of() : Set.copyOf(passFamilies);
        }

        /** The defaults the plan fixes: 3 analyses, a queue of 20, 10 seconds, 3 passes of a read. Off. */
        public static Settings defaults() {
            return new Settings(false, 3, 20, Duration.ofSeconds(40), 3, Set.of(ActionFamily.READ));
        }
    }

    /**
     * One request of an agent.
     *
     * @param subjectKey           the key the agent's decisions are stored under
     * @param contextHash          the context binding the decision is bound to
     * @param sensitive            whether the resource is sensitive (a flight of its own per resource)
     * @param explicitlyNonSensitive whether the host declared the resource non-sensitive (a candidate for a pass)
     * @param sync                 whether the protected method is synchronous: the engine decides every such request on
     *                             its own (A7-2), so no ALLOW anchor answers it and it is one flight per resource
     */
    public record Request(String subjectKey, @Nullable String contextHash, ActionFamily operation,
                          @Nullable String resource, boolean sensitive, boolean explicitlyNonSensitive,
                          boolean sync) {

        public Request(String subjectKey, @Nullable String contextHash, ActionFamily operation,
                       @Nullable String resource, boolean sensitive, boolean explicitlyNonSensitive) {
            this(subjectKey, contextHash, operation, resource, sensitive, explicitlyNonSensitive, false);
        }

        /** A sensitive or synchronous request is decided resource by resource; a general one by the kind of operation. */
        String flightKey() {
            return subjectKey + '\u0000' + contextHash + '\u0000' + operation + '\u0000'
                    + (sensitive || sync ? resource : "*");
        }
    }

    /** What the flights read of the engine's stored state. */
    public interface Ground {

        /** The restriction in force for the request's subject (BLOCK, ESCALATE, CHALLENGE), else null. */
        @Nullable
        ZeroTrustAction restriction(Request request);

        /** Whether an ALLOW anchor answers the request. An answered request counts against the anchor. */
        boolean covered(Request request);

        /**
         * Whether the ALLOW that ended the flight this request joined answers it. The request asked the same question
         * as the one that led, at the same time, so the anchor's request limit does not count it; the limits of the
         * resources, the operation and the context hold.
         */
        boolean coveredJoined(Request request);

        /** Whether a decision for the request's subject and context is now stored. */
        boolean decisionLanded(Request request);

        /**
         * The background analysis that began with this request ended with an ALLOW: the anchor it makes is recorded, as
         * an analysis in the request makes it. The pipeline that ran in the background does not.
         */
        void allowed(Request leader);
    }

    /** How a request ended. */
    public enum Kind {
        /** This request led: it was analysed, and {@code value} is what its analysis gave. */
        LED,
        /** An ALLOW anchor answers it. */
        COVERED,
        /** A restriction in force answers it, {@code restriction}. */
        RESTRICTED,
        /** The leader it followed failed with {@code failure}. */
        FAILED,
        /** The engine could not take it in the time or the queue it has: it is refused, not passed. */
        BUSY
    }

    /**
     * @param analysed whether this very request was analysed (it led): a request analysed is recorded by its analysis,
     *                 one answered without it is recorded by whoever answers it
     */
    public record Result<R>(Kind kind, @Nullable R value, @Nullable ZeroTrustAction restriction,
                            @Nullable Throwable failure, boolean analysed) {

        static <R> Result<R> led(R value) {
            return new Result<>(Kind.LED, value, null, null, true);
        }

        static <R> Result<R> covered() {
            return new Result<>(Kind.COVERED, null, null, null, false);
        }

        static <R> Result<R> restricted(ZeroTrustAction restriction) {
            return new Result<>(Kind.RESTRICTED, null, restriction, null, false);
        }

        /** The request was analysed, and the final gate found a restriction stored meanwhile: the restriction answers. */
        static <R> Result<R> restrictedAfterAnalysis(ZeroTrustAction restriction) {
            return new Result<>(Kind.RESTRICTED, null, restriction, null, true);
        }

        static <R> Result<R> failed(Throwable failure) {
            return new Result<>(Kind.FAILED, null, null, failure, false);
        }

        static <R> Result<R> busy() {
            return new Result<>(Kind.BUSY, null, null, null, false);
        }
    }

    /** Whether a request passes before the verdict, and whether it starts the analysis that decides. */
    public enum Pass {
        NONE,
        /** It passes and its event is analysed in the background: the flight of the verdict that is pending. */
        LEAD,
        /** It passes and an analysis is already pending: it is recorded, not analysed. */
        FOLLOW
    }

    public record Counters(long flights, long followers, long restricted, long busy, long passes, long fallbacks) {
    }

    /** One analysis in progress, in the foreground (a leader's) or in the background (a pass's). */
    private static final class Flight {

        final CountDownLatch finished = new CountDownLatch(1);
        final boolean background;
        final boolean sensitive;
        /** The request that began a background analysis; its ALLOW makes the anchor. */
        @Nullable
        final Request leader;
        final AtomicBoolean anchored = new AtomicBoolean();
        final long startedAt = System.nanoTime();
        volatile Throwable failure;
        volatile boolean abandoned;

        Flight(boolean background, boolean sensitive, @Nullable Request leader) {
            this.background = background;
            this.sensitive = sensitive;
            this.leader = leader;
        }
    }

    /** What one subject has going on. All fields are guarded by the state itself. */
    private static final class SubjectState {

        final Map<String, Flight> flights = new HashMap<>();
        int running;
        int sensitiveRunning;
        int queued;
        int passes;
        long passesSince;
    }

    private final Settings settings;
    private final Map<String, SubjectState> states = new ConcurrentHashMap<>();
    private final AtomicLong flightCount = new AtomicLong();
    private final AtomicLong followerCount = new AtomicLong();
    private final AtomicLong restrictedCount = new AtomicLong();
    private final AtomicLong busyCount = new AtomicLong();
    private final AtomicLong passCount = new AtomicLong();
    private final AtomicLong fallbackCount = new AtomicLong();

    public AgentDecisionFlights(Settings settings) {
        this.settings = settings != null ? settings : Settings.defaults();
    }

    public boolean enabled() {
        return settings.enabled();
    }

    public Settings settings() {
        return settings;
    }

    public Counters counters() {
        return new Counters(flightCount.get(), followerCount.get(), restrictedCount.get(), busyCount.get(),
                passCount.get(), fallbackCount.get());
    }

    /**
     * Decides how the request is taken: answered by a restriction or an anchor, analysed as leader, answered after the
     * leader it followed, or refused as busy. The analysis runs on the caller's thread and only for a leader.
     */
    public <R> Result<R> execute(Request request, Ground ground, Callable<R> analysis) throws Exception {
        if (!settings.enabled()) {
            return Result.led(analysis.call());
        }
        long deadline = System.nanoTime() + settings.maxWait().toNanos();
        SubjectState state = states.computeIfAbsent(request.subjectKey(), key -> new SubjectState());
        boolean queued = false;
        boolean joined = false;
        Throwable[] fromAnalysis = new Throwable[1];
        try {
            while (true) {
                Flight toFollow;
                Flight mine;
                ZeroTrustAction restriction = ground.restriction(request);
                if (restriction != null) {
                    restrictedCount.incrementAndGet();
                    return Result.restricted(restriction);
                }
                if ((joined && ground.coveredJoined(request)) || ground.covered(request)) {
                    return Result.covered();
                }
                joined = false;
                synchronized (state) {
                    toFollow = state.flights.get(request.flightKey());
                    mine = null;
                    if (toFollow == null) {
                        if (state.running < settings.maxInFlightAnalyses()) {
                            mine = new Flight(false, request.sensitive(), null);
                            state.flights.put(request.flightKey(), mine);
                            state.running++;
                            if (request.sensitive()) {
                                state.sensitiveRunning++;
                            }
                            if (queued) {
                                state.queued--;
                                queued = false;
                            }
                        } else {
                            if (!queued) {
                                if (state.queued >= settings.queueCapacity()) {
                                    busyCount.incrementAndGet();
                                    return Result.busy();
                                }
                                state.queued++;
                                queued = true;
                            }
                            long remaining = deadline - System.nanoTime();
                            if (remaining <= 0) {
                                state.queued--;
                                queued = false;
                                busyCount.incrementAndGet();
                                return Result.busy();
                            }
                            state.wait(Math.max(1L, Math.min(POLL_MILLIS, TimeUnit.NANOSECONDS.toMillis(remaining))));
                            continue;
                        }
                    } else if (queued) {
                        state.queued--;
                        queued = false;
                    }
                }
                if (mine != null) {
                    // The look at the top of the loop is older than this place: a restriction may have been stored, and
                    // the place freed by the analysis that stored it, in between. Look again with the place in hand, so
                    // that no analysis begins after a restriction is stored (the final gate would refuse its answer,
                    // but the model call would be spent).
                    ZeroTrustAction stored;
                    try {
                        stored = ground.restriction(request);
                    } catch (RuntimeException unreadable) {
                        end(request, state, mine);
                        throw unreadable;
                    }
                    if (stored != null) {
                        end(request, state, mine);
                        restrictedCount.incrementAndGet();
                        return Result.restricted(stored);
                    }
                    return lead(request, ground, state, mine, analysis, fromAnalysis);
                }
                followerCount.incrementAndGet();
                Result<R> followed = follow(request, ground, toFollow, deadline);
                if (followed != null) {
                    return followed;
                }
                // The flight it joined has ended with a verdict: the next look asks whether that verdict answers it.
                joined = true;
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw interrupted;
        } catch (RuntimeException machinery) {
            if (fromAnalysis[0] == machinery) {
                throw machinery;
            }
            // A failure of the flights themselves is no decision: the request is analysed on its own, as before.
            fallbackCount.incrementAndGet();
            log.error("[AgentDecisionFlights] The flights failed; the request is analysed on its own: subject={}",
                    request.subjectKey(), machinery);
            return Result.led(analysis.call());
        } finally {
            if (queued) {
                synchronized (state) {
                    state.queued--;
                }
            }
        }
    }

    /** The leader's analysis, then the final gate: the restriction in force right before the request is released. */
    private <R> Result<R> lead(Request request, Ground ground, SubjectState state, Flight flight,
                               Callable<R> analysis, Throwable[] fromAnalysis) throws Exception {
        flightCount.incrementAndGet();
        R value;
        try {
            value = analysis.call();
        } catch (InterruptedException interrupted) {
            flight.abandoned = true;
            end(request, state, flight);
            Thread.currentThread().interrupt();
            throw interrupted;
        } catch (Exception | Error failure) {
            // The analysis' own failure is the leader's answer and every follower's; it is no failure of the flights.
            flight.failure = failure;
            fromAnalysis[0] = failure;
            end(request, state, flight);
            throw failure;
        }
        end(request, state, flight);
        ZeroTrustAction restriction = readRestriction(ground, request);
        if (restriction != null) {
            restrictedCount.incrementAndGet();
            return Result.restrictedAfterAnalysis(restriction);
        }
        return Result.led(value);
    }

    private ZeroTrustAction readRestriction(Ground ground, Request request) {
        try {
            return ground.restriction(request);
        } catch (RuntimeException unreadable) {
            // The gate could not read the stored state; the analysis' own answer stands, as it did before.
            fallbackCount.incrementAndGet();
            log.error("[AgentDecisionFlights] The final gate could not read the stored state: subject={}",
                    request.subjectKey(), unreadable);
            return null;
        }
    }

    private void end(Request request, SubjectState state, Flight flight) {
        synchronized (state) {
            if (state.flights.remove(request.flightKey(), flight)) {
                state.running--;
                if (flight.sensitive) {
                    state.sensitiveRunning--;
                }
            }
            state.notifyAll();
        }
        flight.finished.countDown();
        if (states.size() > IDLE_SUBJECTS_KEPT) {
            states.entrySet().removeIf(entry -> idle(entry.getValue()));
        }
    }

    private static boolean idle(SubjectState state) {
        synchronized (state) {
            return state.flights.isEmpty() && state.queued == 0 && state.passes == 0;
        }
    }

    /**
     * Waits for the flight to end. Returns the follower's own result when it is known (a restriction, a failure, busy),
     * or null when the flight is over and the request is to be looked at again: an anchor may answer it, or it leads.
     */
    private <R> Result<R> follow(Request request, Ground ground, Flight flight, long deadline) throws Exception {
        while (true) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                busyCount.incrementAndGet();
                return Result.busy();
            }
            long slice = Math.max(1L, Math.min(POLL_MILLIS, TimeUnit.NANOSECONDS.toMillis(remaining)));
            if (flight.finished.await(slice, TimeUnit.MILLISECONDS)) {
                if (flight.failure != null) {
                    return Result.failed(flight.failure);
                }
                return null;
            }
            ZeroTrustAction restriction = ground.restriction(request);
            if (restriction != null) {
                restrictedCount.incrementAndGet();
                return Result.restricted(restriction);
            }
            if (flight.background && ground.decisionLanded(request)) {
                // A background analysis has no thread to end it: its verdict landing in the store is its end. An
                // ALLOW makes the anchor that answers the requests that waited for it.
                ZeroTrustAction landed = ground.restriction(request);
                if (landed != null) {
                    // The verdict that landed is a restriction: it answers, and it makes no anchor.
                    restrictedCount.incrementAndGet();
                    retire(request, flight);
                    return Result.restricted(landed);
                }
                synchronized (flight) {
                    // One follower makes the anchor and the others wait for it, so that none looks for it too early.
                    if (flight.anchored.compareAndSet(false, true) && flight.leader != null) {
                        ground.allowed(flight.leader);
                    }
                }
                retire(request, flight);
                return null;
            }
            if (flight.background && System.nanoTime() - flight.startedAt > TimeUnit.MILLISECONDS.toNanos(PASS_WINDOW_MILLIS)) {
                retire(request, flight);
                return null;
            }
        }
    }

    private void retire(Request request, Flight flight) {
        SubjectState state = states.get(request.subjectKey());
        if (state != null) {
            end(request, state, flight);
        } else {
            flight.finished.countDown();
        }
    }

    /**
     * Whether a request may pass before the first verdict is in. It may when the host declared the resource
     * non-sensitive, the operation is of an allowed kind, no restriction is in force, no sensitive analysis is running
     * for the subject, and fewer requests than the budget have passed since the last verdict. The first to pass leads
     * the background analysis that decides (the caller publishes its event); the others pass and are only recorded.
     */
    public Pass tryPass(Request request, Ground ground) {
        if (!settings.enabled() || settings.passBudget() <= 0 || !request.explicitlyNonSensitive()
                || request.sensitive() || !settings.passFamilies().contains(request.operation())) {
            return Pass.NONE;
        }
        try {
            if (ground.restriction(request) != null) {
                return Pass.NONE;
            }
            SubjectState state = states.computeIfAbsent(request.subjectKey(), key -> new SubjectState());
            synchronized (state) {
                long now = System.nanoTime();
                if (state.passes > 0 && now - state.passesSince > TimeUnit.MILLISECONDS.toNanos(PASS_WINDOW_MILLIS)) {
                    state.passes = 0;
                }
                if (state.sensitiveRunning > 0 || state.passes >= settings.passBudget()) {
                    return Pass.NONE;
                }
                state.passes++;
                passCount.incrementAndGet();
                if (state.passes == 1) {
                    state.passesSince = now;
                    if (!state.flights.containsKey(request.flightKey()) && state.running < settings.maxInFlightAnalyses()) {
                        state.flights.put(request.flightKey(), new Flight(true, false, request));
                        state.running++;
                        return Pass.LEAD;
                    }
                    return Pass.FOLLOW;
                }
                return Pass.FOLLOW;
            }
        } catch (RuntimeException machinery) {
            fallbackCount.incrementAndGet();
            log.error("[AgentDecisionFlights] A pass could not be decided: subject={}", request.subjectKey(), machinery);
            return Pass.NONE;
        }
    }

    /** A verdict for the subject is stored: the next pending window starts from nothing. */
    public void verdictSeen(String subjectKey) {
        SubjectState state = subjectKey != null ? states.get(subjectKey) : null;
        if (state == null) {
            return;
        }
        synchronized (state) {
            state.passes = 0;
            // The background flights of the subject end with their verdict.
            state.flights.values().removeIf(flight -> {
                if (flight.background) {
                    state.running--;
                    flight.finished.countDown();
                    return true;
                }
                return false;
            });
            state.notifyAll();
        }
    }
}
