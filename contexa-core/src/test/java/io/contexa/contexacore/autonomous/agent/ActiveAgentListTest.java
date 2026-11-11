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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.security.subject.AgentClientStatusUnavailableException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class ActiveAgentListTest {

    private static final Duration LONG = Duration.ofHours(1);

    private final AtomicLong nanos = new AtomicLong();
    private ActiveAgentList list;

    @AfterEach
    void stop() {
        if (list != null) {
            list.stop();
        }
    }

    /** A registry whose readings can be made to fail or to wait, and that counts what is asked of it. */
    private static class ControlledRegistry extends InMemoryAgentRegistry {

        final AtomicBoolean failing = new AtomicBoolean();
        final AtomicInteger approvalReads = new AtomicInteger();
        final AtomicInteger clientLookups = new AtomicInteger();
        volatile CountDownLatch readStarted;
        volatile CountDownLatch readMayEnd;

        @Override
        public List<AgentApproval> approvals(int limit) {
            approvalReads.incrementAndGet();
            if (failing.get()) {
                throw new IllegalStateException("registry unavailable");
            }
            List<AgentApproval> read = super.approvals(limit);
            CountDownLatch started = readStarted;
            CountDownLatch mayEnd = readMayEnd;
            if (started != null && mayEnd != null) {
                started.countDown();
                try {
                    mayEnd.await();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
            return read;
        }

        @Override
        public Optional<AgentRegistration> findByClientId(String tenantId, String clientId) {
            clientLookups.incrementAndGet();
            return super.findByClientId(tenantId, clientId);
        }
    }

    private ActiveAgentList listOf(AgentRegistry registry, Duration staleAfter, int limit) {
        return new ActiveAgentList(registry, nanos::get, LONG, staleAfter, Duration.ofSeconds(5), limit);
    }

    private static void register(AgentRegistry registry, String agentId, String clientId) {
        registry.register(new AgentRegistrationRequest(null, agentId, agentId, "AGENT", clientId, "sponsor", true));
    }

    @Test
    void aListThatWasNotReadCannotSayThatAClientIsNoAgent() {
        ControlledRegistry registry = new ControlledRegistry();
        register(registry, "report-bot", "report-client");
        list = listOf(registry, Duration.ofSeconds(15), 100);

        assertThatThrownBy(() -> list.activeAgent(null, "report-client"))
                .isInstanceOf(AgentClientStatusUnavailableException.class);

        list.refresh();
        assertThat(list.activeAgent(null, "report-client")).contains("report-bot");
    }

    @Test
    void aReadingThatFailsLeavesTheListUnreadableAndIsReportedOncePerMinute() {
        ControlledRegistry registry = new ControlledRegistry();
        registry.failing.set(true);
        list = listOf(registry, Duration.ofSeconds(15), 100);
        ListAppender<ILoggingEvent> logged = new ListAppender<>();
        Logger logger = (Logger) LoggerFactory.getLogger(ActiveAgentList.class);
        logged.start();
        logger.addAppender(logged);
        try {
            for (int attempt = 0; attempt < 5; attempt++) {
                list.refresh();
            }
            assertThatThrownBy(() -> list.activeAgent(null, "report-client"))
                    .isInstanceOf(AgentClientStatusUnavailableException.class)
                    .hasMessageNotContaining("registry unavailable");
            assertThat(errors(logged)).hasSize(1);

            nanos.addAndGet(TimeUnit.SECONDS.toNanos(61));
            list.refresh();
            assertThat(errors(logged)).as("a minute later, it is said again").hasSize(2);
        } finally {
            logger.detachAppender(logged);
        }
    }

    @Test
    void theListGoesOnAnsweringFromWhatItReadForAWhileWhenTheRegistryDoesNotAnswer() {
        ControlledRegistry registry = new ControlledRegistry();
        register(registry, "report-bot", "report-client");
        list = listOf(registry, Duration.ofSeconds(15), 100);
        list.refresh();

        registry.failing.set(true);
        nanos.addAndGet(TimeUnit.SECONDS.toNanos(14));
        list.refresh();
        assertThat(list.activeAgent(null, "report-client")).contains("report-bot");

        nanos.addAndGet(TimeUnit.SECONDS.toNanos(2));
        assertThatThrownBy(() -> list.activeAgent(null, "report-client"))
                .isInstanceOf(AgentClientStatusUnavailableException.class);
        assertThatThrownBy(() -> list.activeAgent(null, "someone-else"))
                .as("a person's account is not told apart from an agent's once the list cannot be trusted")
                .isInstanceOf(AgentClientStatusUnavailableException.class);

        registry.failing.set(false);
        list.refresh();
        assertThat(list.activeAgent(null, "report-client")).contains("report-bot");
        assertThat(list.activeAgent(null, "someone-else")).isEmpty();
    }

    @Test
    void moreRegistrationsThanTheLimitCannotBeKeptAndLeaveTheListUnreadable() {
        ControlledRegistry registry = new ControlledRegistry();
        register(registry, "bot-1", "client-1");
        register(registry, "bot-2", "client-2");
        register(registry, "bot-3", "client-3");
        list = listOf(registry, Duration.ofSeconds(15), 2);

        list.refresh();

        assertThatThrownBy(() -> list.activeAgent(null, "client-1"))
                .as("a list that left an agent out would read the agent as a person")
                .isInstanceOf(AgentClientStatusUnavailableException.class);
    }

    @Test
    void aRequestIsAnsweredWithoutAskingTheRegistryAndWithoutWaitingForIt() {
        ControlledRegistry registry = new ControlledRegistry();
        register(registry, "report-bot", "report-client");
        list = listOf(registry, Duration.ofSeconds(15), 100);
        list.refresh();
        int reads = registry.approvalReads.get();
        CountDownLatch registryBack = new CountDownLatch(1);
        registry.readStarted = new CountDownLatch(1);
        registry.readMayEnd = registryBack;
        Thread reading = new Thread(list::refresh, "reading-the-registry");
        reading.start();
        try {
            assertThat(awaitStarted(registry.readStarted)).as("the registry is held in a reading").isTrue();

            assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
                for (int request = 0; request < 10_000; request++) {
                    assertThat(list.activeAgent(null, "report-client")).contains("report-bot");
                    assertThat(list.activeAgent(null, "alice")).isEmpty();
                }
            });
            assertThat(registry.clientLookups.get()).as("no lookup of a client in the registry").isZero();
            assertThat(registry.approvalReads.get()).as("no reading for a request").isEqualTo(reads + 1);
        } finally {
            registryBack.countDown();
            join(reading);
        }
    }

    @Test
    void aChangeMadeInThisJvmShowsAtOnceAndNoReadingThatBeganBeforeItTakesItBack() throws Exception {
        ControlledRegistry registry = new ControlledRegistry();
        register(registry, "report-bot", "report-client");
        list = new ActiveAgentList(registry, nanos::get, LONG, Duration.ofSeconds(15), Duration.ofSeconds(5), 100);
        list.start();
        assertThat(list.activeAgent(null, "report-client")).contains("report-bot");

        // a reading begins and takes its copy of the registry while the agent is in service ...
        CountDownLatch registryBack = new CountDownLatch(1);
        registry.readStarted = new CountDownLatch(1);
        registry.readMayEnd = registryBack;
        Thread reading = new Thread(list::refresh, "reading-the-registry");
        reading.start();
        try {
            assertThat(awaitStarted(registry.readStarted)).isTrue();

            // ... then the agent is suspended in this JVM ...
            registry.suspend(null, "report-bot", "stopped");
            assertThat(list.activeAgent(null, "report-client")).as("at once").isEmpty();
        } finally {
            // ... and the reading ends: what it took is older than the suspension, so it is not kept
            registryBack.countDown();
            join(reading);
        }
        assertThat(list.activeAgent(null, "report-client")).as("the older reading did not bring it back").isEmpty();
    }

    @Test
    void aChangeNoJvmToldOfShowsWhenTheRegistryIsReadAgain() {
        ControlledRegistry registry = new ControlledRegistry();
        list = listOf(registry, Duration.ofSeconds(15), 100);
        list.refresh();
        assertThat(list.activeAgent(null, "report-client")).isEmpty();

        register(registry, "report-bot", "report-client");
        assertThat(list.activeAgent(null, "report-client"))
                .as("a list that is not listening (not started) is not told")
                .isEmpty();

        list.refresh();
        assertThat(list.activeAgent(null, "report-client")).contains("report-bot");
    }

    @Test
    void theStartReadsTheRegistryBeforeItReturnsAndReadsItAgainInTheBackground() throws Exception {
        ControlledRegistry registry = new ControlledRegistry();
        register(registry, "report-bot", "report-client");
        list = new ActiveAgentList(registry, System::nanoTime, Duration.ofMillis(50), Duration.ofSeconds(15),
                Duration.ofSeconds(5), 100);

        list.start();

        assertThat(registry.approvalReads.get()).isGreaterThanOrEqualTo(1);
        assertThat(list.activeAgent(null, "report-client")).contains("report-bot");
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (registry.approvalReads.get() < 4 && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        assertThat(registry.approvalReads.get()).as("read again by itself").isGreaterThanOrEqualTo(4);
    }

    @Test
    void aStartWhoseRegistryDoesNotAnswerGoesOnAfterTheWaitAndTheListIsReadWhenItAnswers() throws Exception {
        ControlledRegistry registry = new ControlledRegistry();
        register(registry, "report-bot", "report-client");
        CountDownLatch registryBack = new CountDownLatch(1);
        registry.readStarted = new CountDownLatch(1);
        registry.readMayEnd = registryBack;
        list = new ActiveAgentList(registry, System::nanoTime, Duration.ofMillis(50), Duration.ofSeconds(15),
                Duration.ofMillis(200), 100);
        ListAppender<ILoggingEvent> logged = new ListAppender<>();
        Logger logger = (Logger) LoggerFactory.getLogger(ActiveAgentList.class);
        logged.start();
        logger.addAppender(logged);
        try {
            long begun = System.nanoTime();
            list.start();
            assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - begun)).as("the start does not hold").isLessThan(3000);

            assertThat(errors(logged)).hasSize(1);
            assertThatThrownBy(() -> list.activeAgent(null, "report-client"))
                    .isInstanceOf(AgentClientStatusUnavailableException.class);
        } finally {
            logger.detachAppender(logged);
        }

        registry.readStarted = null;
        registryBack.countDown();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            try {
                assertThat(list.activeAgent(null, "report-client")).contains("report-bot");
                return;
            } catch (AgentClientStatusUnavailableException notYet) {
                Thread.sleep(20);
            }
        }
        assertThat(list.activeAgent(null, "report-client")).contains("report-bot");
    }

    @Test
    void aListThatIsNotAskedToListenIsNotChangedByAListenerThatFails() {
        ControlledRegistry registry = new ControlledRegistry();
        registry.onApprovalChange(change -> {
            throw new IllegalStateException("a listener that fails");
        });

        AgentRegistration registered = registry.register(new AgentRegistrationRequest(null, "report-bot", "Report bot",
                "AGENT", "report-client", "sponsor", true));

        assertThat(registered.agentId()).isEqualTo("report-bot");
        assertThat(registry.find(null, "report-bot")).isPresent();
    }

    private static boolean awaitStarted(CountDownLatch started) {
        try {
            return started.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static void join(Thread thread) {
        try {
            thread.join(5000);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static List<ILoggingEvent> errors(ListAppender<ILoggingEvent> logged) {
        return logged.list.stream().filter(event -> event.getLevel() == Level.ERROR).toList();
    }
}
