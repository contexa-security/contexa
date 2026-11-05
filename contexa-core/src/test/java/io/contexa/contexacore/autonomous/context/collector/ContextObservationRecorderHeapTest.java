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
package io.contexa.contexacore.autonomous.context.collector;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-91: every request stages a snapshot of its session, which holds up to a hundred decoded decisions, and 10,000 of
 * them filled a customer's heap. What the requests hold now has a size limit of its own: committed requests give their
 * snapshots up first, the oldest first, and their marks stay. Nothing a decision reads changes.
 */
class ContextObservationRecorderHeapTest {

    private static final long BUDGET_BYTES = 1L << 20;
    private static final int DECISIONS = 100;
    private static final String SESSION = "session-heap";
    private static final Instant STARTED = Instant.parse("2026-11-05T09:00:00Z");

    @Test
    void committedRequestsKeepTheirSnapshotsWithinTheBudgetTheNewestStayingAndEveryMarkStays() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store, BUDGET_BYTES);
        List<SecurityEvent> events = new ArrayList<>();

        for (int request = 0; request < 300; request++) {
            SecurityEvent event = event("request-" + request);
            events.add(event);
            recorder.stage(event, ContextObservationRecorder.SESSION_NARRATIVE, narrative(request), commit -> {
            });
            recorder.commit(event, "ALLOW", true);
        }

        int kept = keptSnapshots(recorder, events);
        assertThat(kept).as("snapshots still held").isPositive().isLessThan(100);
        assertThat(recorder.heldBytes()).isLessThanOrEqualTo(BUDGET_BYTES);
        assertThat(resolved(recorder, events.get(events.size() - 1))).isPresent();
        assertThat(resolved(recorder, events.get(0))).isEmpty();

        // A snapshot given up leaves the request committed: it is not recorded a second time.
        assertThat(events).allMatch(recorder::committed);
        int decisions = store.getRecentSessionDecisions(SESSION, 1_000).size();
        recorder.commit(events.get(0), "BLOCK", true);
        assertThat(store.getRecentSessionDecisions(SESSION, 1_000)).hasSize(decisions);
    }

    @Test
    void aRequestWaitingForItsDecisionKeepsItsSnapshotAndObservationsWhileCommittedRequestsGo() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store, BUDGET_BYTES);
        SecurityEvent waiting = event("request-waiting");
        List<String> recorded = new ArrayList<>();
        SessionNarrativeSnapshot snapshot = narrative(0);
        recorder.stage(waiting, ContextObservationRecorder.SESSION_NARRATIVE, snapshot,
                commit -> recorded.add(commit.outcome()));

        for (int request = 0; request < 300; request++) {
            SecurityEvent event = event("request-" + request);
            recorder.stage(event, ContextObservationRecorder.SESSION_NARRATIVE, narrative(request), commit -> {
            });
            recorder.commit(event, "ALLOW", true);
        }

        assertThat(resolved(recorder, waiting)).containsSame(snapshot);
        recorder.commit(waiting, "CHALLENGE", true);
        assertThat(recorded).containsExactly("CHALLENGE");
    }

    @Test
    void requestsThatNeverReachACommitStayWithinTheBudgetTheOldestGoingFirst() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store, BUDGET_BYTES);
        List<SecurityEvent> events = new ArrayList<>();
        List<String> recorded = new ArrayList<>();

        for (int request = 0; request < 300; request++) {
            SecurityEvent event = event("request-" + request);
            events.add(event);
            recorder.stage(event, ContextObservationRecorder.SESSION_NARRATIVE, narrative(request),
                    commit -> recorded.add(event.getEventId()));
        }

        assertThat(keptSnapshots(recorder, events)).isPositive().isLessThan(100);
        assertThat(recorder.heldBytes()).isLessThanOrEqualTo(BUDGET_BYTES);
        assertThat(resolved(recorder, events.get(events.size() - 1))).isPresent();
        assertThat(resolved(recorder, events.get(0))).isEmpty();

        // The commit that does come still records the decision; only what was given up is not there to run.
        recorder.commit(events.get(0), "ALLOW", true);
        assertThat(recorded).isEmpty();
        assertThat(store.getRecentSessionDecisions(SESSION, 10)).hasSize(1);
    }

    @Test
    void aSnapshotCountsForItsSizeSoLongUrlsDoNotOutgrowTheBudget() {
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore(),
                BUDGET_BYTES);
        List<SecurityEvent> events = new ArrayList<>();
        String query = "q=" + "x".repeat(8_000);

        for (int request = 0; request < 50; request++) {
            SecurityEvent event = event("request-" + request);
            events.add(event);
            SessionNarrativeSnapshot snapshot = SessionNarrativeSnapshot.builder()
                    .sessionId(SESSION)
                    .sessionDecisions(decisions(request, query))
                    .build();
            recorder.stage(event, ContextObservationRecorder.SESSION_NARRATIVE, snapshot, commit -> {
            });
            recorder.commit(event, "ALLOW", true);
        }

        // One such snapshot is more than the budget: none is kept, whatever their count.
        assertThat(keptSnapshots(recorder, events)).isZero();
        assertThat(recorder.heldBytes()).isLessThanOrEqualTo(BUDGET_BYTES);
    }

    @Test
    void whatTheCacheDropsLeavesNothingCountedOrHeldBehind() {
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore(),
                BUDGET_BYTES * 1024);

        for (int request = 0; request < 15_000; request++) {
            SecurityEvent event = event("request-" + request);
            recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, "snapshot", commit -> {
            });
            recorder.commit(event, "ALLOW", true);
        }

        assertThat(recorder.heldRequests()).isLessThanOrEqualTo(10_000);
        assertThat(recorder.heldBytes()).isLessThanOrEqualTo(10_000L * 1_024);
    }

    /** Many requests at once, past the budget and past the number of requests: the count stays exact and nothing waits. */
    @Test
    void theCountStaysExactWhenRequestsRaceTheBudgetAndTheCache() throws InterruptedException {
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore(),
                BUDGET_BYTES);
        int threads = 8;
        int requests = 3_000;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<SecurityEvent> events = Collections.synchronizedList(new ArrayList<>());

        for (int thread = 0; thread < threads; thread++) {
            int offset = thread * requests;
            executor.execute(() -> {
                for (int request = offset; request < offset + requests; request++) {
                    SecurityEvent event = event("request-" + request);
                    events.add(event);
                    recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, "snapshot-" + request, commit -> {
                    });
                    recorder.stage(event, ContextObservationRecorder.ROLE_SCOPE, "x".repeat(request % 2_000), commit -> {
                    });
                    recorder.resolved(event, ContextObservationRecorder.WORK_PROFILE, String.class);
                    if (request % 7 != 0) {
                        recorder.commit(event, "ALLOW", true);
                    }
                }
            });
        }
        executor.shutdown();

        assertThat(executor.awaitTermination(2, TimeUnit.MINUTES)).as("no request waits for another for ever").isTrue();
        assertThat(recorder.heldBytes()).isLessThanOrEqualTo(BUDGET_BYTES);
        events.forEach(recorder::release);
        assertThat(recorder.heldRequests()).isZero();
        assertThat(recorder.heldBytes()).isZero();
    }

    @Test
    void aReleasedRequestKeepsOnlyItsMark() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store, BUDGET_BYTES);
        SecurityEvent event = event("request-1");
        List<String> recorded = new ArrayList<>();
        recorder.stage(event, ContextObservationRecorder.SESSION_NARRATIVE, narrative(0),
                commit -> recorded.add(commit.outcome()));
        assertThat(recorder.staged(event)).isTrue();
        recorder.commit(event, "ALLOW", true);

        recorder.release(event);

        assertThat(recorder.staged(event)).isFalse();
        assertThat(resolved(recorder, event)).isEmpty();
        assertThat(recorder.committed(event)).isTrue();
        assertThat(recorder.heldBytes()).isZero();
        recorder.commit(event, "BLOCK", true);
        recorder.stage(event, ContextObservationRecorder.SESSION_NARRATIVE, narrative(1), commit -> recorded.add("later"));
        assertThat(recorded).containsExactly("ALLOW");
        assertThat(recorder.staged(event)).isFalse();
        assertThat(store.getRecentSessionDecisions(SESSION, 10)).hasSize(1);
    }

    /** Requests of one session, as the load of PR-91 made them: the decoded decisions held stop growing. */
    @Test
    void aLongSessionKeepsFewDecodedDecisions() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store, BUDGET_BYTES);
        DefaultSessionNarrativeCollector collector = new DefaultSessionNarrativeCollector(store, recorder);
        List<SecurityEvent> events = new ArrayList<>();

        for (int request = 0; request < 1_000; request++) {
            SecurityEvent event = sessionRequest(request);
            events.add(event);
            collector.collect(event);
            recorder.commit(event, "ALLOW", true);
        }

        long decoded = events.stream()
                .map(event -> resolved(recorder, event))
                .flatMap(Optional::stream)
                .mapToLong(snapshot -> snapshot.getSessionDecisions().size())
                .sum();
        assertThat(decoded).as("decoded decisions held").isLessThan(10_000);
    }

    /** What a decision reads does not depend on what the requests before it gave up. */
    @Test
    void theBudgetChangesNothingANewRequestReads() {
        InMemorySecurityContextDataStore wideStore = new InMemorySecurityContextDataStore();
        InMemorySecurityContextDataStore narrowStore = new InMemorySecurityContextDataStore();
        ContextObservationRecorder wide = new ContextObservationRecorder(wideStore, Long.MAX_VALUE);
        ContextObservationRecorder narrow = new ContextObservationRecorder(narrowStore, 200_000L);
        DefaultSessionNarrativeCollector wideCollector = new DefaultSessionNarrativeCollector(wideStore, wide);
        DefaultSessionNarrativeCollector narrowCollector = new DefaultSessionNarrativeCollector(narrowStore, narrow);

        for (int request = 0; request < 150; request++) {
            SecurityEvent event = sessionRequest(request);
            SessionNarrativeSnapshot wideSnapshot = wideCollector.collect(event).orElseThrow();
            SessionNarrativeSnapshot narrowSnapshot = narrowCollector.collect(event).orElseThrow();
            assertThat(narrowSnapshot).isEqualTo(wideSnapshot);
            wide.commit(event, "ALLOW", true);
            narrow.commit(event, "ALLOW", true);
        }

        assertThat(narrowStore.getRecentSessionDecisions(SESSION, 200))
                .isEqualTo(wideStore.getRecentSessionDecisions(SESSION, 200));
    }

    @Test
    void aRequestWhoseSnapshotWentIsReadAgainWithoutBeingRecordedTwice() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store, BUDGET_BYTES);
        DefaultSessionNarrativeCollector collector = new DefaultSessionNarrativeCollector(store, recorder);
        SecurityEvent event = sessionRequest(0);
        collector.collect(event);
        recorder.commit(event, "ALLOW", true);
        List<String> actions = store.getRecentSessionNarrativeActionFamilies(SESSION, 10);

        recorder.release(event);
        Optional<SessionNarrativeSnapshot> again = collector.collect(event);
        recorder.commit(event, "ALLOW", true);

        assertThat(again).isPresent();
        assertThat(store.getRecentSessionDecisions(SESSION, 10)).hasSize(1);
        assertThat(store.getRecentSessionNarrativeActionFamilies(SESSION, 10)).isEqualTo(actions);
    }

    @Test
    void theBudgetIsATwentiethOfTheHeapWithinItsBounds() {
        long mebibyte = 1024L * 1024;
        assertThat(ContextObservationRecorder.defaultHeldBudgetBytes(128 * mebibyte)).isEqualTo(16 * mebibyte);
        assertThat(ContextObservationRecorder.defaultHeldBudgetBytes(512 * mebibyte))
                .isEqualTo(512 * mebibyte / 20);
        assertThat(ContextObservationRecorder.defaultHeldBudgetBytes(2_048 * mebibyte))
                .isEqualTo(2_048 * mebibyte / 20);
        assertThat(ContextObservationRecorder.defaultHeldBudgetBytes(Long.MAX_VALUE)).isEqualTo(256 * mebibyte);
    }

    private static int keptSnapshots(ContextObservationRecorder recorder, List<SecurityEvent> events) {
        return (int) events.stream().filter(event -> resolved(recorder, event).isPresent()).count();
    }

    private static Optional<SessionNarrativeSnapshot> resolved(ContextObservationRecorder recorder, SecurityEvent event) {
        return recorder.resolved(event, ContextObservationRecorder.SESSION_NARRATIVE, SessionNarrativeSnapshot.class);
    }

    private static SessionNarrativeSnapshot narrative(int request) {
        return SessionNarrativeSnapshot.builder()
                .sessionId(SESSION)
                .sessionDecisions(decisions(request, null))
                .summary("Session age 3m | Previous path /api/orders/" + request)
                .build();
    }

    /** The decisions as the collector decodes them: the same facts of each request, in objects of their own. */
    private static List<SessionDecisionRecord> decisions(int request, String query) {
        List<SessionDecisionRecord> decisions = new ArrayList<>();
        for (int decision = 0; decision < DECISIONS; decision++) {
            decisions.add(SessionDecisionRecord.decode(new SessionDecisionRecord(STARTED.plusSeconds(request + decision),
                    "GET", "/api/orders/" + decision, query, "READ", "ALLOW").encode()));
        }
        return decisions;
    }

    private static SecurityEvent event(String requestId) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-" + requestId)
                .sessionId(SESSION)
                .timestamp(STARTED)
                .build();
        event.addMetadata("requestId", requestId);
        return event;
    }

    private static SecurityEvent sessionRequest(int request) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-" + request)
                .sessionId(SESSION)
                .userId("alice")
                .timestamp(STARTED.plusSeconds(request))
                .build();
        event.addMetadata("requestId", "request-" + request);
        event.addMetadata("requestPath", "/api/orders/" + request);
        event.addMetadata("httpMethod", "GET");
        return event;
    }
}
