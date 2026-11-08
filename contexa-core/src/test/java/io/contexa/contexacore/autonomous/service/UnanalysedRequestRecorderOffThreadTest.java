package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.context.collector.SessionNarrativeCollector;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

/**
 * The session record of a request answered by the decision in force (N-SES-1) is made off the request's thread: the
 * request has been answered, and the record only feeds the decisions that come later, so the request does not wait for
 * the dozens of Redis commands it takes. The records of one session keep their order, and a line that is full is not
 * a lost record: the thread that asks makes it.
 */
@Timeout(value = 30, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class UnanalysedRequestRecorderOffThreadTest {

    private final SessionNarrativeCollector collector = mock(SessionNarrativeCollector.class);
    private final ContextObservationRecorder recorder = mock(ContextObservationRecorder.class);
    private final List<String> recorded = new CopyOnWriteArrayList<>();
    private final List<String> threads = new CopyOnWriteArrayList<>();
    private final CountDownLatch release = new CountDownLatch(1);
    private SessionRecordingLine line;

    @AfterEach
    void tearDown() {
        release.countDown();
        if (line != null) {
            line.destroy();
        }
    }

    private void collecting(boolean blocked) {
        doAnswer(call -> {
            SecurityEvent event = call.getArgument(0);
            if (blocked) {
                release.await();
            }
            recorded.add(String.valueOf(event.getMetadata().get("requestId")));
            threads.add(Thread.currentThread().getName());
            return null;
        }).when(collector).collect(any(SecurityEvent.class));
    }

    private static ZeroTrustSpringEvent event(String session, String requestId) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("requestId", requestId);
        payload.put("httpMethod", "GET");
        payload.put("requestPath", "/api/customers/CUS-0012");
        payload.put("granted", true);
        return ZeroTrustSpringEvent.builder(UnanalysedRequestRecorderOffThreadTest.class)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("alice")
                .sessionId(session)
                .resource("/api/customers/CUS-0012")
                .eventTimestamp(Instant.parse("2026-11-08T00:00:00Z"))
                .payload(payload)
                .build();
    }

    @Test
    void aRecordIsMadeOnAnotherThreadAndTheRequestDoesNotWaitForIt() {
        collecting(true);
        line = new SessionRecordingLine(2, 8);
        UnanalysedRequestRecorder unanalysed = new UnanalysedRequestRecorder(collector, recorder, null, null, line);

        long began = System.nanoTime();
        unanalysed.record(event("session-1", "r1"), ZeroTrustAction.ALLOW);
        long tookMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began);

        assertThat(tookMillis).isLessThan(1_000L);
        assertThat(recorded).isEmpty();
        release.countDown();
        Awaitility.await().untilAsserted(() -> assertThat(recorded).containsExactly("r1"));
        assertThat(threads).doesNotContain(Thread.currentThread().getName());
    }

    @Test
    void theRecordsOfOneSessionKeepTheirOrder() {
        collecting(false);
        line = new SessionRecordingLine(4, 100);
        UnanalysedRequestRecorder unanalysed = new UnanalysedRequestRecorder(collector, recorder, null, null, line);

        for (int index = 0; index < 40; index++) {
            unanalysed.record(event("session-1", "r" + index), ZeroTrustAction.ALLOW);
        }

        Awaitility.await().untilAsserted(() -> assertThat(recorded).hasSize(40));
        for (int index = 0; index < 40; index++) {
            assertThat(recorded.get(index)).isEqualTo("r" + index);
        }
    }

    @Test
    void aFullLineIsNoLostRecordTheThreadThatAsksMakesIt() {
        collecting(true);
        line = new SessionRecordingLine(1, 1);
        UnanalysedRequestRecorder unanalysed = new UnanalysedRequestRecorder(collector, recorder, null, null, line);
        // the first record holds the only thread of the line, the second fills its place
        unanalysed.record(event("session-1", "r1"), ZeroTrustAction.ALLOW);
        Awaitility.await().until(() -> true);
        unanalysed.record(event("session-1", "r2"), ZeroTrustAction.ALLOW);
        Thread asking = new Thread(() -> unanalysed.record(event("session-1", "r3"), ZeroTrustAction.ALLOW), "asking");
        asking.start();

        // r3 finds the line full and is made by the asking thread, which waits for the collector as the others do
        release.countDown();
        Awaitility.await().untilAsserted(() -> assertThat(recorded).containsExactlyInAnyOrder("r1", "r2", "r3"));
        assertThat(threads).contains("asking");
    }

    @Test
    void aStoppedLineFinishesWhatWasQueued() {
        collecting(false);
        line = new SessionRecordingLine(1, 50);
        UnanalysedRequestRecorder unanalysed = new UnanalysedRequestRecorder(collector, recorder, null, null, line);
        for (int index = 0; index < 20; index++) {
            unanalysed.record(event("session-1", "r" + index), ZeroTrustAction.ALLOW);
        }

        line.destroy();

        assertThat(recorded).hasSize(20);
    }

    @Test
    void withoutALineTheRecordIsMadeOnTheCallersThread() {
        collecting(false);
        UnanalysedRequestRecorder unanalysed = new UnanalysedRequestRecorder(collector, recorder, null, null);

        unanalysed.record(event("session-1", "r1"), ZeroTrustAction.ALLOW);

        assertThat(recorded).containsExactly("r1");
        assertThat(threads).containsExactly(Thread.currentThread().getName());
    }
}
