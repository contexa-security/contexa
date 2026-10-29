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
import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights.Ground;
import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights.Kind;
import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights.Pass;
import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights.Request;
import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights.Result;
import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights.Settings;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RL-12: what the flights decide, by structure and not by verdict. The analysis is a script (delays and answers set
 * by the test), the ground is a model of the stored state and of an agent's allow-reuse anchors with the real limits
 * (10 requests, 3 resources, 1 sensitive resource), and every check is a count: analyses started, analyses running
 * at once, the answer each request got, and the requests let through.
 */
class AgentDecisionFlightsTest {

    private static final String SUBJECT = "alice:agent-7";
    private static final String CONTEXT = "context-1";

    /** The stored state and the anchors, as the engine keeps them. */
    private static final class ModelGround implements Ground {

        private final AgentAllowReuse reuse = new AgentAllowReuse(10, 3, 1, null);
        private final AtomicReference<ZeroTrustAction> restriction = new AtomicReference<>();
        private final AtomicInteger decisionsLanded = new AtomicInteger();

        @Override
        public ZeroTrustAction restriction(Request request) {
            return restriction.get();
        }

        @Override
        public boolean covered(Request request) {
            if (request.sync()) {
                return false;   // A7-2: a synchronous request is decided on its own; no anchor answers it
            }
            return reuse.answers(request.subjectKey(), request.contextHash(), request.operation(), request.resource(),
                    request.sensitive());
        }

        @Override
        public boolean coveredJoined(Request request) {
            if (request.sync()) {
                return false;
            }
            return reuse.answersJoined(request.subjectKey(), request.contextHash(), request.operation(), request.resource(),
                    request.sensitive());
        }

        @Override
        public boolean decisionLanded(Request request) {
            return decisionsLanded.get() > 0 || restriction.get() != null;
        }

        @Override
        public void allowed(Request leader) {
            reuse.decided(leader.subjectKey(), leader.contextHash(), leader.operation(), leader.resource(),
                    leader.sensitive());
        }

        /** What the background pipeline does when its analysis ends: the decision is stored, no anchor is made. */
        void landInTheBackground(ZeroTrustAction action) {
            decisionsLanded.incrementAndGet();
            if (action != ZeroTrustAction.ALLOW) {
                restriction.compareAndSet(null, action);
            }
        }

        /** What the engine does when an analysis ends: a restriction is stored, an ALLOW makes an anchor. */
        void store(Request request, ZeroTrustAction action) {
            decisionsLanded.incrementAndGet();
            if (action == ZeroTrustAction.ALLOW) {
                reuse.decided(request.subjectKey(), request.contextHash(), request.operation(), request.resource(),
                        request.sensitive());
            } else {
                restriction.compareAndSet(null, action);
            }
        }
    }

    /** A scripted analysis: how long it takes and what it answers, counting itself and how many run at once. */
    private static class Script {

        final AtomicInteger started = new AtomicInteger();
        final AtomicInteger running = new AtomicInteger();
        final AtomicInteger mostAtOnce = new AtomicInteger();
        final long millis;
        final Function<Request, ZeroTrustAction> answer;
        final ModelGround ground;

        Script(ModelGround ground, long millis, Function<Request, ZeroTrustAction> answer) {
            this.ground = ground;
            this.millis = millis;
            this.answer = answer;
        }

        Callable<ZeroTrustAction> analysisOf(Request request) {
            return () -> {
                started.incrementAndGet();
                int now = running.incrementAndGet();
                mostAtOnce.accumulateAndGet(now, Math::max);
                try {
                    Thread.sleep(millis);
                    ZeroTrustAction action = answer.apply(request);
                    ground.store(request, action);
                    return action;
                } finally {
                    running.decrementAndGet();
                }
            };
        }
    }

    private static Settings settings(int inFlight, int queue, long waitMillis, int passBudget) {
        return new Settings(true, inFlight, queue, Duration.ofMillis(waitMillis), passBudget, Set.of(ActionFamily.READ));
    }

    private static Request general(String resource) {
        return new Request(SUBJECT, CONTEXT, ActionFamily.READ, resource, false, false);
    }

    private static Request sensitive(String resource) {
        return new Request(SUBJECT, CONTEXT, ActionFamily.READ, resource, true, false);
    }

    private static Request explicitlyNonSensitive(String resource) {
        return new Request(SUBJECT, CONTEXT, ActionFamily.READ, resource, false, true);
    }

    /** What each of N concurrent requests got. */
    private static List<Result<ZeroTrustAction>> runTogether(AgentDecisionFlights flights, ModelGround ground,
                                                              Script script, List<Request> requests) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(requests.size());
        try {
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Result<ZeroTrustAction>>> futures = new ArrayList<>();
            for (Request request : requests) {
                futures.add(pool.submit(() -> {
                    go.await();
                    return flights.execute(request, ground, script.analysisOf(request));
                }));
            }
            go.countDown();
            List<Result<ZeroTrustAction>> results = new ArrayList<>();
            for (Future<Result<ZeroTrustAction>> future : futures) {
                results.add(future.get(30, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private static long answeredAllow(List<Result<ZeroTrustAction>> results) {
        return results.stream().filter(r -> r.kind() == Kind.COVERED
                || (r.kind() == Kind.LED && r.value() == ZeroTrustAction.ALLOW)).count();
    }

    private static long restricted(List<Result<ZeroTrustAction>> results) {
        return results.stream().filter(r -> r.kind() == Kind.RESTRICTED
                || (r.kind() == Kind.LED && r.value() != ZeroTrustAction.ALLOW)).count();
    }

    private static List<Request> same(int count, String resource) {
        List<Request> requests = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            requests.add(general(resource));
        }
        return requests;
    }

    // FL-01
    @RepeatedTest(200)
    void tenConcurrentRequestsForTheSameResourceAreOneAnalysis() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 5_000, 3));
        Script script = new Script(ground, 80, request -> ZeroTrustAction.ALLOW);

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, same(10, "DOC-1"));

        assertThat(script.started.get()).isEqualTo(1);
        assertThat(answeredAllow(results)).isEqualTo(10);
    }

    // FL-02
    @RepeatedTest(200)
    void elevenConcurrentRequestsForTheSameResourceAreStillOneAnalysis() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 5_000, 3));
        Script script = new Script(ground, 80, request -> ZeroTrustAction.ALLOW);

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, same(11, "DOC-1"));

        assertThat(script.started.get()).as("the requests that joined the flight do not count against the request limit")
                .isEqualTo(1);
        assertThat(answeredAllow(results)).isEqualTo(11);
    }

    // FL-03
    @RepeatedTest(200)
    void fiftyConcurrentRequestsForTheSameResourceAreOneAnalysis() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 60, 20_000, 3));
        Script script = new Script(ground, 40, request -> ZeroTrustAction.ALLOW);

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, same(50, "DOC-1"));

        assertThat(script.started.get()).isEqualTo(1);
        assertThat(answeredAllow(results)).isEqualTo(50);
        assertThat(script.mostAtOnce.get()).isEqualTo(1);
    }

    // FL-22: a burst of two hundred; the requests that come after it are counted against the request limit as before
    @RepeatedTest(20)
    void twoHundredConcurrentRequestsForTheSameResourceAreOneAnalysisAndLaterOnesStillCount() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 30_000, 3));
        Script script = new Script(ground, 500, request -> ZeroTrustAction.ALLOW);

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, same(200, "DOC-1"));

        assertThat(script.started.get()).isEqualTo(1);
        assertThat(answeredAllow(results)).isEqualTo(200);
        assertThat(results.stream().filter(r -> r.kind() == Kind.BUSY).count()).isZero();
        // nine more requests are answered by that ALLOW, the tenth is decided again
        for (int later = 0; later < 9; later++) {
            Result<ZeroTrustAction> result = flights.execute(general("DOC-1"), ground, () -> {
                throw new AssertionError("a later request inside the limit is not analysed");
            });
            assertThat(result.kind()).isEqualTo(Kind.COVERED);
        }
        assertThat(flights.execute(general("DOC-1"), ground, script.analysisOf(general("DOC-1"))).kind())
                .isEqualTo(Kind.LED);
        assertThat(script.started.get()).isEqualTo(2);
    }

    // FL-04
    @RepeatedTest(200)
    void threeDistinctGeneralResourcesAreOneAnalysisAndFourAreTwo() throws Exception {
        ModelGround three = new ModelGround();
        Script threeScript = new Script(three, 80, request -> ZeroTrustAction.ALLOW);
        List<Result<ZeroTrustAction>> threeResults = runTogether(new AgentDecisionFlights(settings(3, 20, 5_000, 3)),
                three, threeScript, List.of(general("DOC-1"), general("DOC-2"), general("DOC-3")));
        assertThat(threeScript.started.get()).isEqualTo(1);
        assertThat(answeredAllow(threeResults)).isEqualTo(3);

        ModelGround four = new ModelGround();
        Script fourScript = new Script(four, 80, request -> ZeroTrustAction.ALLOW);
        List<Result<ZeroTrustAction>> fourResults = runTogether(new AgentDecisionFlights(settings(3, 20, 5_000, 3)),
                four, fourScript, List.of(general("DOC-1"), general("DOC-2"), general("DOC-3"), general("DOC-4")));
        assertThat(fourScript.started.get()).isEqualTo(2);
        assertThat(answeredAllow(fourResults)).isEqualTo(4);
    }

    // FL-05
    @RepeatedTest(200)
    void eightDistinctGeneralResourcesAreThreeAnalyses() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 10_000, 3));
        Script script = new Script(ground, 60, request -> ZeroTrustAction.ALLOW);
        List<Request> requests = new ArrayList<>();
        for (int i = 1; i <= 8; i++) {
            requests.add(general("DOC-" + i));
        }

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, requests);

        assertThat(script.started.get()).isEqualTo(3);
        assertThat(answeredAllow(results)).isEqualTo(8);
    }

    // FL-06
    @RepeatedTest(200)
    void aLeaderThatBlocksBlocksEveryFollowerWithOneAnalysis() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 40, 5_000, 3));
        Script script = new Script(ground, 80, request -> ZeroTrustAction.BLOCK);

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, same(21, "DOC-1"));

        assertThat(script.started.get()).isEqualTo(1);
        assertThat(restricted(results)).isEqualTo(21);
        assertThat(results).allSatisfy(r -> assertThat(r.kind()).isIn(Kind.LED, Kind.RESTRICTED));
    }

    // FL-07
    @RepeatedTest(100)
    void aLeaderThatFailsFailsEveryFollowerAndNoneAnalysesAgain() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 40, 5_000, 3));
        AtomicInteger started = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Object>> futures = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                Request request = general("DOC-1");
                futures.add(pool.submit(() -> {
                    go.await();
                    try {
                        return flights.execute(request, ground, () -> {
                            started.incrementAndGet();
                            Thread.sleep(80);
                            throw new IllegalStateException("model unavailable");
                        });
                    } catch (IllegalStateException leaderFailure) {
                        return leaderFailure;
                    }
                }));
            }
            go.countDown();
            int leaders = 0;
            int followers = 0;
            for (Future<Object> future : futures) {
                Object outcome = future.get(30, TimeUnit.SECONDS);
                if (outcome instanceof IllegalStateException) {
                    leaders++;
                } else {
                    Result<?> result = (Result<?>) outcome;
                    assertThat(result.kind()).isEqualTo(Kind.FAILED);
                    assertThat(result.failure()).isInstanceOf(IllegalStateException.class).hasMessage("model unavailable");
                    followers++;
                }
            }
            assertThat(started.get()).isEqualTo(1);
            assertThat(leaders).isEqualTo(1);
            assertThat(followers).isEqualTo(7);
        } finally {
            pool.shutdownNow();
        }
    }

    // FL-08
    @RepeatedTest(100)
    void fiveSensitiveResourcesAreFiveAnalysesWithAtMostThreeAtOnce() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 10_000, 3));
        Script script = new Script(ground, 100, request -> ZeroTrustAction.ALLOW);
        List<Request> requests = new ArrayList<>();
        for (int i = 1; i <= 5; i++) {
            requests.add(sensitive("CUS-" + i));
        }

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, requests);

        assertThat(script.started.get()).isEqualTo(5);
        assertThat(script.mostAtOnce.get()).isEqualTo(3);
        assertThat(answeredAllow(results)).isEqualTo(5);
    }

    // FL-09
    @RepeatedTest(100)
    void whenTheFirstAnalysisBlocksTheOthersAreBlockedWithoutOrAtTheFinalGate() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 10_000, 3));
        CountDownLatch firstStored = new CountDownLatch(1);
        // The first analysis to start answers BLOCK at once; the other two running wait for it, then answer ALLOW.
        Script script = new Script(ground, 0, request -> ZeroTrustAction.ALLOW) {
            @Override
            Callable<ZeroTrustAction> analysisOf(Request request) {
                return () -> {
                    int order = started.incrementAndGet();
                    Thread.sleep(50);
                    if (order == 1) {
                        ground.store(request, ZeroTrustAction.BLOCK);
                        firstStored.countDown();
                        return ZeroTrustAction.BLOCK;
                    }
                    firstStored.await(5, TimeUnit.SECONDS);
                    ground.store(request, ZeroTrustAction.ALLOW);
                    return ZeroTrustAction.ALLOW;
                };
            }
        };
        List<Request> requests = new ArrayList<>();
        for (int i = 1; i <= 5; i++) {
            requests.add(sensitive("CUS-" + i));
        }

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, requests);

        assertThat(script.started.get()).isEqualTo(3);
        assertThat(restricted(results)).as("every request is blocked").isEqualTo(5);
        assertThat(answeredAllow(results)).isZero();
    }

    // FL-23: the request read no restriction, then a restriction was stored and the only place was freed, all before the
    // request took the place (the preemption that made FL-09 count four analyses once in 1900 under load)
    @RepeatedTest(50)
    void aRestrictionStoredBetweenTheLookAndTheTakingOfAPlaceStopsTheAnalysis() throws Exception {
        ModelGround model = new ModelGround();
        AtomicInteger lateLooks = new AtomicInteger();
        CountDownLatch lateHasLooked = new CountDownLatch(1);
        CountDownLatch lateMayTakeThePlace = new CountDownLatch(1);
        Ground ground = new Ground() {
            @Override
            public ZeroTrustAction restriction(Request request) {
                return model.restriction(request);
            }

            @Override
            public boolean covered(Request request) {
                // the look at the restriction is behind the late request; here it waits before it takes a place
                if (request.resource().equals("LATE") && lateLooks.incrementAndGet() == 1) {
                    lateHasLooked.countDown();
                    try {
                        lateMayTakeThePlace.await(10, TimeUnit.SECONDS);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                }
                return model.covered(request);
            }

            @Override
            public boolean coveredJoined(Request request) {
                return model.coveredJoined(request);
            }

            @Override
            public boolean decisionLanded(Request request) {
                return model.decisionLanded(request);
            }

            @Override
            public void allowed(Request leader) {
                model.allowed(leader);
            }
        };
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(1, 20, 10_000, 3));
        AtomicInteger started = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Result<ZeroTrustAction>> late = pool.submit(() -> flights.execute(sensitive("LATE"), ground, () -> {
                started.incrementAndGet();
                return ZeroTrustAction.ALLOW;
            }));
            assertThat(lateHasLooked.await(10, TimeUnit.SECONDS)).isTrue();
            // the only place is taken and freed by an analysis that stores a BLOCK, while the late request waits
            Result<ZeroTrustAction> blocking = flights.execute(sensitive("FIRST"), ground, () -> {
                started.incrementAndGet();
                model.store(sensitive("FIRST"), ZeroTrustAction.BLOCK);
                return ZeroTrustAction.BLOCK;
            });
            lateMayTakeThePlace.countDown();
            Result<ZeroTrustAction> result = late.get(10, TimeUnit.SECONDS);

            assertThat(blocking.kind()).isEqualTo(Kind.RESTRICTED);
            assertThat(started.get()).as("no analysis is begun once a restriction is stored").isEqualTo(1);
            assertThat(result.kind()).isEqualTo(Kind.RESTRICTED);
            assertThat(result.restriction()).isEqualTo(ZeroTrustAction.BLOCK);
            assertThat(flights.counters().flights()).isEqualTo(1);
        } finally {
            lateMayTakeThePlace.countDown();
            pool.shutdownNow();
        }
    }

    // FL-10, FL-11
    @Test
    void whatTheQueueAndTheWaitCannotHoldIsBusyAndNeverPassed() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 400, 3));
        Script script = new Script(ground, 1_500, request -> ZeroTrustAction.ALLOW);
        List<Request> requests = new ArrayList<>();
        for (int i = 1; i <= 30; i++) {
            requests.add(sensitive("CUS-" + i));
        }

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, requests);

        long busy = results.stream().filter(r -> r.kind() == Kind.BUSY).count();
        // 3 analyses run, 20 wait in the queue, the other 7 find it full; the 20 queued ones outwait the 400 ms and are busy too.
        assertThat(script.mostAtOnce.get()).isEqualTo(3);
        assertThat(script.started.get()).isEqualTo(3);
        assertThat(busy).isEqualTo(27);
        assertThat(results.stream().filter(r -> r.kind() == Kind.LED).count()).isEqualTo(3);
        assertThat(results.stream().filter(r -> r.kind() == Kind.COVERED).count())
                .as("no request is answered without a verdict").isZero();
    }

    // FL-12
    @Test
    void aRestrictionStoredWhileAFollowerWaitsAnswersItAtOnce() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 10_000, 3));
        CountDownLatch leaderRunning = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Result<ZeroTrustAction>> leader = pool.submit(() -> flights.execute(general("DOC-1"), ground, () -> {
                leaderRunning.countDown();
                Thread.sleep(3_000);
                return ZeroTrustAction.ALLOW;
            }));
            assertThat(leaderRunning.await(5, TimeUnit.SECONDS)).isTrue();
            long begin = System.nanoTime();
            Future<Result<ZeroTrustAction>> follower = pool.submit(() ->
                    flights.execute(general("DOC-1"), ground, () -> ZeroTrustAction.ALLOW));
            Thread.sleep(150);
            ground.store(general("DOC-9"), ZeroTrustAction.BLOCK);

            Result<ZeroTrustAction> answer = follower.get(5, TimeUnit.SECONDS);

            assertThat(answer.kind()).isEqualTo(Kind.RESTRICTED);
            assertThat(answer.restriction()).isEqualTo(ZeroTrustAction.BLOCK);
            assertThat(Duration.ofNanos(System.nanoTime() - begin)).as("not after the leader's 3 s")
                    .isLessThan(Duration.ofMillis(2_000));
            leader.cancel(true);
        } finally {
            pool.shutdownNow();
        }
    }

    // FL-13
    @Test
    void twoContextsOfOneSubjectAreTwoFlightsUnderOneLimit() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 10_000, 3));
        Script script = new Script(ground, 100, request -> ZeroTrustAction.ALLOW);
        List<Request> requests = new ArrayList<>();
        for (int i = 1; i <= 6; i++) {
            requests.add(new Request(SUBJECT, "context-" + (i % 2), ActionFamily.READ, "CUS-" + i, true, false));
        }

        runTogether(flights, ground, script, requests);

        assertThat(script.started.get()).isEqualTo(6);
        assertThat(script.mostAtOnce.get()).as("the limit is the subject's, not the context's").isEqualTo(3);
    }

    // FL-15
    @Test
    void withTheFlightsOffEveryRequestIsAnalysedAsItWasBefore() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(new Settings(false, 3, 20, Duration.ofSeconds(5), 3,
                Set.of(ActionFamily.READ)));
        Script script = new Script(ground, 60, request -> ZeroTrustAction.ALLOW);

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, same(10, "DOC-1"));

        assertThat(script.started.get()).isEqualTo(10);
        assertThat(results).allSatisfy(r -> assertThat(r.kind()).isEqualTo(Kind.LED));
        assertThat(flights.counters().flights()).isZero();
        assertThat(flights.tryPass(explicitlyNonSensitive("DOC-1"), ground)).isEqualTo(Pass.NONE);
    }

    // FL-16
    @Test
    void aFlightMachineryFailureFallsBackToAnAnalysisPerRequestAndPassesNothing() throws Exception {
        ModelGround healthy = new ModelGround();
        Ground broken = new Ground() {
            @Override
            public ZeroTrustAction restriction(Request request) {
                throw new IllegalStateException("store down");
            }

            @Override
            public boolean covered(Request request) {
                throw new IllegalStateException("store down");
            }

            @Override
            public boolean coveredJoined(Request request) {
                throw new IllegalStateException("store down");
            }

            @Override
            public boolean decisionLanded(Request request) {
                throw new IllegalStateException("store down");
            }

            @Override
            public void allowed(Request leader) {
                throw new IllegalStateException("store down");
            }
        };
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 5_000, 3));
        AtomicInteger started = new AtomicInteger();

        Result<ZeroTrustAction> result = flights.execute(general("DOC-1"), broken, () -> {
            started.incrementAndGet();
            return ZeroTrustAction.ALLOW;
        });

        assertThat(result.kind()).isEqualTo(Kind.LED);
        assertThat(started.get()).isEqualTo(1);
        assertThat(flights.tryPass(explicitlyNonSensitive("DOC-1"), broken)).isEqualTo(Pass.NONE);
        assertThat(healthy.reuse).isNotNull();
    }

    // FL-17
    @Test
    void aLeaderThatIsInterruptedLeavesTheFlightToAFollower() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 10_000, 3));
        AtomicInteger started = new AtomicInteger();
        CountDownLatch leaderRunning = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Result<ZeroTrustAction>> leader = pool.submit(() -> flights.execute(general("DOC-1"), ground, () -> {
                started.incrementAndGet();
                leaderRunning.countDown();
                Thread.sleep(10_000);
                return ZeroTrustAction.ALLOW;
            }));
            assertThat(leaderRunning.await(5, TimeUnit.SECONDS)).isTrue();
            Future<Result<ZeroTrustAction>> follower = pool.submit(() -> flights.execute(general("DOC-1"), ground, () -> {
                started.incrementAndGet();
                ground.store(general("DOC-1"), ZeroTrustAction.ALLOW);
                return ZeroTrustAction.ALLOW;
            }));
            Thread.sleep(150);

            leader.cancel(true);

            Result<ZeroTrustAction> answer = follower.get(5, TimeUnit.SECONDS);
            assertThat(answer.kind()).isEqualTo(Kind.LED);
            assertThat(started.get()).isEqualTo(2);
        } finally {
            pool.shutdownNow();
        }
    }

    // FL-19 (fan-out of a normal agent): eight parallel general reads of one project are one analysis
    @RepeatedTest(100)
    void aNormalFanOutOfOneOperationOverFewResourcesIsNotOverBlocked() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 5_000, 3));
        Script script = new Script(ground, 60, request -> ZeroTrustAction.ALLOW);
        List<Request> requests = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            requests.add(general(i < 4 ? "DOC-1" : i < 7 ? "DOC-2" : "DOC-3"));
        }

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, requests);

        assertThat(script.started.get()).isEqualTo(1);
        assertThat(answeredAllow(results)).isEqualTo(8);
        assertThat(results).noneMatch(r -> r.kind() == Kind.BUSY || r.kind() == Kind.RESTRICTED);
    }

    // FL-20: a synchronous request is decided on its own; only a restriction answers it early
    @RepeatedTest(50)
    void synchronousRequestsAreEachDecidedOneAfterAnotherUnderOneLimit() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 20_000, 3));
        Script script = new Script(ground, 20, request -> ZeroTrustAction.ALLOW);
        List<Request> requests = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            requests.add(new Request(SUBJECT, CONTEXT, ActionFamily.EXPORT, "GB-500", false, false, true));
        }

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, requests);

        assertThat(script.started.get()).as("no verdict is shared").isEqualTo(5);
        assertThat(script.mostAtOnce.get()).as("the same resource is one flight at a time").isEqualTo(1);
        assertThat(results).allSatisfy(r -> assertThat(r.kind()).isEqualTo(Kind.LED));
    }

    // FL-21
    @RepeatedTest(50)
    void aBlockOnASynchronousRequestBlocksTheOthersWithoutAnalysingThem() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 20_000, 3));
        Script script = new Script(ground, 40, request -> ZeroTrustAction.BLOCK);
        List<Request> requests = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            requests.add(new Request(SUBJECT, CONTEXT, ActionFamily.EXPORT, "GB-500", false, false, true));
        }

        List<Result<ZeroTrustAction>> results = runTogether(flights, ground, script, requests);

        assertThat(script.started.get()).isEqualTo(1);
        assertThat(restricted(results)).isEqualTo(5);
    }

    // PB-01
    @RepeatedTest(200)
    void withinTheBudgetNonSensitiveReadsPassAndTheRestWaitForTheOneAnalysis() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 5_000, 3));
        List<Pass> passes = new ArrayList<>();
        for (int i = 1; i <= 3; i++) {
            passes.add(flights.tryPass(explicitlyNonSensitive("DOC-" + i), ground));
        }
        passes.add(flights.tryPass(explicitlyNonSensitive("DOC-4"), ground));
        passes.add(flights.tryPass(explicitlyNonSensitive("DOC-5"), ground));

        assertThat(passes).containsExactly(Pass.LEAD, Pass.FOLLOW, Pass.FOLLOW, Pass.NONE, Pass.NONE);

        // The two that wait find the background analysis as the flight they follow; its verdict answers them.
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            AtomicInteger analyses = new AtomicInteger();
            List<Future<Result<ZeroTrustAction>>> waiting = new ArrayList<>();
            for (int i = 4; i <= 5; i++) {
                Request request = explicitlyNonSensitive("DOC-" + i);
                waiting.add(pool.submit(() -> flights.execute(request, ground, () -> {
                    analyses.incrementAndGet();
                    return ZeroTrustAction.ALLOW;
                })));
            }
            Thread.sleep(150);
            assertThat(waiting).noneMatch(Future::isDone);

            // The background analysis ends: its ALLOW is stored; the flights make the anchor and release the waiting ones.
            ground.landInTheBackground(ZeroTrustAction.ALLOW);
            for (Future<Result<ZeroTrustAction>> future : waiting) {
                assertThat(future.get(5, TimeUnit.SECONDS).kind()).isEqualTo(Kind.COVERED);
            }
            assertThat(analyses.get()).as("no analysis of their own").isZero();
        } finally {
            pool.shutdownNow();
        }
    }

    // PB-03, PB-04, PB-05, PB-06, PB-08
    @Test
    void onlyAnExplicitNonSensitiveReadOfAnAllowedFamilyMayPass() {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 5_000, 3));

        assertThat(flights.tryPass(new Request(SUBJECT, CONTEXT, ActionFamily.EXPORT, "DOC-1", false, true), ground))
                .as("an export").isEqualTo(Pass.NONE);
        assertThat(flights.tryPass(new Request(SUBJECT, CONTEXT, ActionFamily.READ, "DOC-1", false, false), ground))
                .as("unspecified").isEqualTo(Pass.NONE);
        assertThat(flights.tryPass(sensitive("CUS-1"), ground)).as("sensitive").isEqualTo(Pass.NONE);

        AgentDecisionFlights noBudget = new AgentDecisionFlights(settings(3, 20, 5_000, 0));
        assertThat(noBudget.tryPass(explicitlyNonSensitive("DOC-1"), ground)).as("a budget of 0").isEqualTo(Pass.NONE);
    }

    // PB-02
    @Test
    void aVerdictThatLandsEndsThePassesAndARestrictionIsNeverPassedOver() {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 5_000, 3));
        assertThat(flights.tryPass(explicitlyNonSensitive("DOC-1"), ground)).isEqualTo(Pass.LEAD);
        assertThat(flights.tryPass(explicitlyNonSensitive("DOC-2"), ground)).isEqualTo(Pass.FOLLOW);

        ground.store(explicitlyNonSensitive("DOC-1"), ZeroTrustAction.BLOCK);

        assertThat(flights.tryPass(explicitlyNonSensitive("DOC-3"), ground)).isEqualTo(Pass.NONE);
        flights.verdictSeen(SUBJECT);
        ModelGround allowed = new ModelGround();
        assertThat(flights.tryPass(explicitlyNonSensitive("DOC-4"), allowed)).as("a new pending window")
                .isEqualTo(Pass.LEAD);
    }

    // PB-07
    @Test
    void whileASensitiveAnalysisRunsNothingPasses() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 5_000, 3));
        CountDownLatch running = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<Result<ZeroTrustAction>> sensitiveLeader = pool.submit(() -> flights.execute(sensitive("CUS-1"), ground, () -> {
                running.countDown();
                release.await(5, TimeUnit.SECONDS);
                return ZeroTrustAction.ALLOW;
            }));
            assertThat(running.await(5, TimeUnit.SECONDS)).isTrue();

            assertThat(flights.tryPass(explicitlyNonSensitive("DOC-1"), ground)).isEqualTo(Pass.NONE);

            release.countDown();
            sensitiveLeader.get(5, TimeUnit.SECONDS);
            assertThat(flights.tryPass(explicitlyNonSensitive("DOC-2"), ground)).isEqualTo(Pass.LEAD);
        } finally {
            pool.shutdownNow();
        }
    }

    // GT-01, GT-02
    @Test
    void theFinalGateReadsTheRestrictionRightBeforeAnAllowIsReleased() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 5_000, 3));

        // The analysis ends ALLOW, but a BLOCK was stored by another request while it ran.
        Result<ZeroTrustAction> blocked = flights.execute(sensitive("CUS-1"), ground, () -> {
            ground.restriction.set(ZeroTrustAction.BLOCK);
            return ZeroTrustAction.ALLOW;
        });
        assertThat(blocked.kind()).isEqualTo(Kind.RESTRICTED);
        assertThat(blocked.restriction()).isEqualTo(ZeroTrustAction.BLOCK);

        // A BLOCK stored right after the gate read nothing is the window that stays: the request is released.
        ModelGround later = new ModelGround();
        Result<ZeroTrustAction> released = flights.execute(sensitive("CUS-2"), later, () -> ZeroTrustAction.ALLOW);
        later.restriction.set(ZeroTrustAction.BLOCK);
        assertThat(released.kind()).isEqualTo(Kind.LED);
        assertThat(flights.execute(sensitive("CUS-3"), later, () -> ZeroTrustAction.ALLOW).kind())
                .as("the next request").isEqualTo(Kind.RESTRICTED);
    }

    // The counters report what the flights did.
    @Test
    void theCountersCountFlightsFollowersRestrictionsBusyAndPasses() throws Exception {
        ModelGround ground = new ModelGround();
        AgentDecisionFlights flights = new AgentDecisionFlights(settings(3, 20, 5_000, 3));
        Script script = new Script(ground, 80, request -> ZeroTrustAction.ALLOW);

        runTogether(flights, ground, script, same(10, "DOC-1"));
        flights.tryPass(explicitlyNonSensitive("DOC-1"), new ModelGround());

        AgentDecisionFlights.Counters counters = flights.counters();
        assertThat(counters.flights()).isEqualTo(1);
        assertThat(counters.passes()).isEqualTo(1);
        assertThat(counters.busy()).isZero();
        assertThat(counters.restricted()).isZero();
        assertThat(counters.fallbacks()).isZero();
    }
}
