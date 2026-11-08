package io.contexa.contexacore.autonomous;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * No more analyses run at once than the model servers can serve within the event's budget: the actors follow the limit
 * the model servers give (never above {@code analysis-stripes}), and what does not run yet waits in the line, in its
 * order, with its budget not started.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class SecurityPlaneAgentModelCapacityTest {

    private final SecurityMonitoringService monitor = mock(SecurityMonitoringService.class);
    private final SecurityEventProcessor processor = mock(SecurityEventProcessor.class);
    private final SecurityPlaneProperties properties = new SecurityPlaneProperties();
    private final ExecutorService analysis = Executors.newCachedThreadPool();
    private final CountDownLatch release = new CountDownLatch(1);
    private final List<String> analysed = new CopyOnWriteArrayList<>();
    private final AtomicInteger atOnce = new AtomicInteger();
    private final AtomicInteger mostAtOnce = new AtomicInteger();
    private SecurityMonitoringService.SecurityEventBatchProcessor batches;
    private SecurityPlaneAgent agent;

    @BeforeEach
    void setUp() {
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> {
            SecurityEvent event = call.getArgument(0);
            analysed.add(event.getEventId());
            mostAtOnce.accumulateAndGet(atOnce.incrementAndGet(), Math::max);
            try {
                release.await();
            } finally {
                atOnce.decrementAndGet();
            }
            SecurityEventContext context = SecurityEventContext.builder().securityEvent(event)
                    .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED).build();
            context.addMetadata("processingResult", ProcessingResult.builder().success(true).action("ALLOW")
                    .llmDecisionPresent(true).build());
            return context;
        });
        agent = startedAgent();
        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> captor =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(monitor, atLeast(1)).setBatchProcessor(captor.capture());
        batches = captor.getValue();
    }

    @AfterEach
    void tearDown() {
        release.countDown();
        agent.shutdown();
        analysis.shutdownNow();
    }

    private SecurityPlaneAgent startedAgent() {
        SecurityPlaneAgent started = new SecurityPlaneAgent(monitor, new InMemorySecurityContextDataStore(),
                mock(CentralAuditFacade.class), processor, properties, analysis);
        started.initialize();
        started.start();
        return started;
    }

    private static SecurityEvent request(String user) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("zerotrust.category", "AUTHORIZATION");
        return SecurityEvent.builder().eventId(UUID.randomUUID().toString()).userId(user).sessionId("session-" + user)
                .sourceIp("10.0.0.1").metadata(metadata).build();
    }

    private void users(String prefix, int count) {
        List<SecurityEvent> events = new ArrayList<>();
        for (int user = 0; user < count; user++) {
            events.add(request(prefix + user));
        }
        batches.processBatch(events);
    }

    @Test
    void noMoreAnalysesRunAtOnceThanTheModelServersGive() throws Exception {
        agent.setAnalysisCapacity(() -> 3);

        users("alice-", 10);

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(3));
        Thread.sleep(300);
        assertThat(analysed).hasSize(3);
        assertThat(agent.analysesInProgress()).isEqualTo(10);
    }

    @Test
    void whatWaitsRunsWhenAnAnalysisEnds() {
        agent.setAnalysisCapacity(() -> 2);
        users("bob-", 6);
        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(2));

        release.countDown();

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(6));
        Awaitility.await().untilAsserted(() -> assertThat(agent.analysesInProgress()).isZero());
        assertThat(mostAtOnce.get()).isEqualTo(2);
    }

    @Test
    void aLimitThatGrowsLetsMoreRun() {
        AtomicInteger limit = new AtomicInteger(1);
        agent.setAnalysisCapacity(limit::get);
        users("carol-", 6);
        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(1));

        limit.set(4);
        users("dave-", 1);

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilAsserted(() -> assertThat(analysed).hasSize(4));
    }

    @Test
    void theLimitNeverRaisesTheAnalysisStripes() throws Exception {
        agent.shutdown();
        properties.getAgent().setAnalysisStripes(2);
        agent = startedAgent();
        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> captor =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(monitor, atLeast(2)).setBatchProcessor(captor.capture());
        agent.setAnalysisCapacity(() -> 1_000);

        captor.getValue().processBatch(List.of(request("erin-1"), request("erin-2"), request("erin-3"),
                request("erin-4")));

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(2));
        Thread.sleep(300);
        assertThat(analysed).hasSize(2);
    }

    /** The bean is made, and the limit given, before the actors exist: the first wave of a burst is held to it too. */
    @Test
    void aLimitGivenBeforeTheActorsExistHoldsTheFirstWave() throws Exception {
        agent.shutdown();
        SecurityPlaneAgent early = new SecurityPlaneAgent(monitor, new InMemorySecurityContextDataStore(),
                mock(CentralAuditFacade.class), processor, properties, analysis);
        early.setAnalysisCapacity(() -> 2);
        early.initialize();
        early.start();
        agent = early;
        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> captor =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(monitor, atLeast(2)).setBatchProcessor(captor.capture());

        assertThat(early.analysisActors()).isEqualTo(2);
        captor.getValue().processBatch(List.of(request("gus-1"), request("gus-2"), request("gus-3"),
                request("gus-4")));

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(2));
        Thread.sleep(300);
        assertThat(analysed).hasSize(2);
    }

    /** The capacity only tunes how many run at once: a reading that fails keeps the last one and fails no batch. */
    @Test
    void aCapacityThatCannotBeReadKeepsTheLastOneAndFailsNoBatch() {
        AtomicInteger reads = new AtomicInteger();
        agent.setAnalysisCapacity(() -> {
            if (reads.incrementAndGet() > 1) {
                throw new IllegalStateException("the gates are not readable");
            }
            return 2;
        });

        users("gus-", 5);

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(2));
        assertThat(reads.get()).isGreaterThan(1);
        assertThat(agent.analysisActors()).isEqualTo(2);
        assertThat(agent.analysesInProgress()).isEqualTo(5);
    }

    @Test
    void withoutALimitTheAnalysisStripesAreTheLimit() throws Exception {
        agent.shutdown();
        properties.getAgent().setAnalysisStripes(3);
        agent = startedAgent();
        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> captor =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(monitor, atLeast(2)).setBatchProcessor(captor.capture());

        captor.getValue().processBatch(List.of(request("fay-1"), request("fay-2"), request("fay-3"),
                request("fay-4"), request("fay-5")));

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(3));
        Thread.sleep(300);
        assertThat(analysed).hasSize(3);
    }
}
