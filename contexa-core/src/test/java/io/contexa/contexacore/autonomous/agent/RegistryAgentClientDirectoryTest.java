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
import io.contexa.contexacommon.security.bridge.runtime.RequestPathDatabaseGuard;
import io.contexa.contexacommon.security.subject.AgentClientStatusUnavailableException;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RegistryAgentClientDirectoryTest {

    private final InMemoryAgentRegistry registry =
            new InMemoryAgentRegistry(Clock.fixed(Instant.parse("2026-10-23T01:00:00Z"), ZoneOffset.UTC));
    private final RegistryAgentClientDirectory directory = new RegistryAgentClientDirectory(registry);

    @Test
    void anApprovedAgentInServiceIsNamedByItsRegisteredIdentifier() {
        registry.register(new AgentRegistrationRequest(null, "report-bot", "Report bot", null, "report-client", "carol", null));

        assertThat(directory.activeAgentForClient(null, "report-client")).contains("report-bot");
    }

    @Test
    void anObservedAgentIsNotApproved() {
        registry.observe(new AgentSighting(null, "seen-bot", "AUTONOMOUS_AGENT", "seen-client", Instant.parse("2026-10-23T00:00:00Z")));

        assertThat(directory.activeAgentForClient(null, "seen-client")).isEmpty();
    }

    @Test
    void anAgentRegisteredAsNotApprovedIsNotNamed() {
        registry.register(new AgentRegistrationRequest(null, "draft-bot", "Draft", null, "draft-client", "carol", false));

        assertThat(directory.activeAgentForClient(null, "draft-client")).isEmpty();
    }

    @Test
    void aDeregisteredAgentIsNoLongerNamed() {
        registry.register(new AgentRegistrationRequest(null, "report-bot", "Report bot", null, "report-client", "carol", null));
        registry.deregister(null, "report-bot", "retired");

        assertThat(directory.activeAgentForClient(null, "report-client")).isEmpty();
    }

    @Test
    void theLookupStaysInTheTokensTenant() {
        registry.register(new AgentRegistrationRequest("tenant-acme", "acme-bot", "Acme bot", null, "acme-client", "erin", null));

        assertThat(directory.activeAgentForClient("tenant-acme", "acme-client")).contains("acme-bot");
        assertThat(directory.activeAgentForClient(null, "acme-client")).isEmpty();
        assertThat(directory.activeAgentForClient("tenant-other", "acme-client")).isEmpty();
    }

    /**
     * A registry that fails cannot say that a client is no agent: the answer is "cannot be read", never "no agent", since
     * a caller that read "no agent" would skip what an agent is held to (a delegation revoked, a tenant it belongs to).
     * A directory without a registry, and a blank client, are named no agent as before.
     */
    @Test
    void aRegistryFailureIsUnreadableAndNeverNoAgent() {
        AgentRegistry failing = new InMemoryAgentRegistry() {
            @Override
            public Optional<AgentRegistration> findByClientId(String tenantId, String clientId) {
                throw new IllegalStateException("registry unavailable");
            }

            @Override
            public List<AgentRegistration> findAllByClientId(String clientId) {
                throw new IllegalStateException("registry unavailable");
            }
        };
        RegistryAgentClientDirectory directory = new RegistryAgentClientDirectory(failing);

        assertThatThrownBy(() -> directory.activeAgentForClient(null, "report-client"))
                .isInstanceOf(AgentClientStatusUnavailableException.class)
                .hasMessageNotContaining("registry unavailable");
        assertThatThrownBy(() -> directory.activeAgentForClient("tenant-a", "report-client"))
                .isInstanceOf(AgentClientStatusUnavailableException.class);
        assertThatThrownBy(() -> directory.activeAgentForAccount(null, "report-client"))
                .isInstanceOf(AgentClientStatusUnavailableException.class);
        assertThatThrownBy(() -> directory.tenantOfClient("report-client"))
                .isInstanceOf(AgentClientStatusUnavailableException.class)
                .hasMessageNotContaining("registry unavailable");

        assertThat(new RegistryAgentClientDirectory(null).activeAgentForClient(null, "report-client")).isEmpty();
        assertThat(new RegistryAgentClientDirectory(null).tenantOfClient("report-client")).isEmpty();
        assertThat(List.of(this.directory.activeAgentForClient(null, null), this.directory.activeAgentForClient(null, " ")))
                .allMatch(Optional::isEmpty);
        assertThat(List.of(this.directory.tenantOfClient(null), this.directory.tenantOfClient(" ")))
                .allMatch(Optional::isEmpty);
    }

    /** Each read of the registry stands alone: one that answered before does not make a later one that fails answer. */
    @Test
    void aReadThatFailsAfterOneThatAnsweredIsUnreadableToo() {
        registry.register(new AgentRegistrationRequest("tenant-a", "tenant-bot", "Tenant bot", null, "tenant-client", "carol", null));
        AtomicBoolean failing = new AtomicBoolean();
        AgentRegistry flapping = new InMemoryAgentRegistry() {
            @Override
            public Optional<AgentRegistration> findByClientId(String tenantId, String clientId) {
                return failing.get() ? failed() : registry.findByClientId(tenantId, clientId);
            }

            @Override
            public List<AgentRegistration> findAllByClientId(String clientId) {
                return failing.get() ? failedAll() : registry.findAllByClientId(clientId);
            }

            private Optional<AgentRegistration> failed() {
                throw new IllegalStateException("registry unavailable");
            }

            private List<AgentRegistration> failedAll() {
                throw new IllegalStateException("registry unavailable");
            }
        };
        RegistryAgentClientDirectory directory = new RegistryAgentClientDirectory(flapping);

        assertThat(directory.tenantOfClient("tenant-client")).contains("tenant-a");
        failing.set(true);
        assertThatThrownBy(() -> directory.activeAgentForClient("tenant-a", "tenant-client"))
                .isInstanceOf(AgentClientStatusUnavailableException.class);
        assertThatThrownBy(() -> directory.tenantOfClient("tenant-client"))
                .isInstanceOf(AgentClientStatusUnavailableException.class);
        failing.set(false);
        assertThat(directory.activeAgentForClient("tenant-a", "tenant-client")).contains("tenant-bot");
        assertThat(directory.tenantOfClient("tenant-client")).contains("tenant-a");
    }

    @Test
    void aRegistryThatDoesNotAnswerDoesNotHoldTheRequest() {
        CountDownLatch databaseBack = new CountDownLatch(1);
        AgentRegistry hanging = mock(AgentRegistry.class);
        when(hanging.findByClientId(any(), any())).thenAnswer(call -> {
            databaseBack.await();
            return Optional.empty();
        });
        when(hanging.findAllByClientId(any())).thenAnswer(call -> {
            databaseBack.await();
            return List.of();
        });
        RequestPathDatabaseGuard guard = new RequestPathDatabaseGuard(Duration.ofMillis(150), 4);
        RegistryAgentClientDirectory outage = new RegistryAgentClientDirectory(hanging, guard);
        try {
            assertTimeoutPreemptively(Duration.ofSeconds(3), () -> {
                // The wait ends, and what it ends with is "cannot tell", never "no agent" and never "not suspended".
                assertThatThrownBy(() -> outage.activeAgentForClient(null, "report-client"))
                        .isInstanceOf(AgentClientStatusUnavailableException.class);
                assertThatThrownBy(() -> outage.tenantOfClient("report-client"))
                        .isInstanceOf(AgentClientStatusUnavailableException.class);
                assertThatThrownBy(() -> outage.suspendedAgentClient(null, "report-client"))
                        .isInstanceOf(AgentClientStatusUnavailableException.class);
            });
        } finally {
            databaseBack.countDown();
            guard.destroy();
        }
    }

    /** A failure never lifts a suspension: the status is unreadable, whatever the failure and whichever token asks. */
    @Test
    void aRegistryFailureMakesTheSuspensionUnreadableAndNeverAbsent() {
        AgentRegistry failing = new InMemoryAgentRegistry() {
            @Override
            public Optional<AgentRegistration> findByClientId(String tenantId, String clientId) {
                throw new IllegalStateException("registry unavailable");
            }

            @Override
            public List<AgentRegistration> findAllByClientId(String clientId) {
                throw new IllegalStateException("registry unavailable");
            }
        };
        RegistryAgentClientDirectory directory = new RegistryAgentClientDirectory(failing);

        assertThatThrownBy(() -> directory.suspendedAgentClient(null, "report-client"))
                .isInstanceOf(AgentClientStatusUnavailableException.class)
                .hasMessageNotContaining("registry unavailable");
        assertThatThrownBy(() -> directory.suspendedAgentClient("tenant-a", "report-client"))
                .isInstanceOf(AgentClientStatusUnavailableException.class);
    }

    @Test
    void whenEveryWorkerIsHeldTheSuspensionIsUnreadableAtOnce() {
        CountDownLatch databaseBack = new CountDownLatch(1);
        AgentRegistry hanging = mock(AgentRegistry.class);
        when(hanging.findAllByClientId(any())).thenAnswer(call -> {
            databaseBack.await();
            return List.of();
        });
        RequestPathDatabaseGuard guard = new RequestPathDatabaseGuard(Duration.ofMillis(100), 1);
        RegistryAgentClientDirectory outage = new RegistryAgentClientDirectory(hanging, guard);
        try {
            assertTimeoutPreemptively(Duration.ofSeconds(3), () -> {
                // The first call holds the only worker past its wait; the second finds none free and does not wait.
                assertThatThrownBy(() -> outage.suspendedAgentClient(null, "report-client"))
                        .isInstanceOf(AgentClientStatusUnavailableException.class);
                assertThatThrownBy(() -> outage.suspendedAgentClient(null, "report-client"))
                        .isInstanceOf(AgentClientStatusUnavailableException.class);
            });
        } finally {
            databaseBack.countDown();
            guard.destroy();
        }
    }

    /**
     * The outage is one error line for a client in a minute, not one for every request that meets it, and the line names
     * the client and nothing the registry said.
     */
    @Test
    void anOutageIsReportedOncePerClientInAMinute() {
        AgentRegistry failing = new InMemoryAgentRegistry() {
            @Override
            public List<AgentRegistration> findAllByClientId(String clientId) {
                throw new IllegalStateException("password authentication failed for user contexa");
            }
        };
        AtomicLong nanos = new AtomicLong();
        RequestPathDatabaseGuard guard = new RequestPathDatabaseGuard();
        RegistryAgentClientDirectory directory = new RegistryAgentClientDirectory(failing, guard, nanos::get);
        ListAppender<ILoggingEvent> logged = new ListAppender<>();
        Logger logger = (Logger) LoggerFactory.getLogger(RegistryAgentClientDirectory.class);
        logged.start();
        logger.addAppender(logged);
        try {
            for (int request = 0; request < 5; request++) {
                assertThatThrownBy(() -> directory.suspendedAgentClient(null, "report-client"))
                        .isInstanceOf(AgentClientStatusUnavailableException.class);
            }
            assertThat(errors(logged)).hasSize(1);
            assertThat(errors(logged).get(0).getFormattedMessage()).contains("report-client")
                    .doesNotContain("password");

            nanos.addAndGet(TimeUnit.SECONDS.toNanos(30));
            assertThatThrownBy(() -> directory.suspendedAgentClient(null, "report-client"))
                    .isInstanceOf(AgentClientStatusUnavailableException.class);
            assertThat(errors(logged)).as("still the same minute").hasSize(1);

            assertThatThrownBy(() -> directory.suspendedAgentClient(null, "sync-client"))
                    .isInstanceOf(AgentClientStatusUnavailableException.class);
            assertThat(errors(logged)).as("another client is another line").hasSize(2);

            nanos.addAndGet(TimeUnit.SECONDS.toNanos(31));
            assertThatThrownBy(() -> directory.suspendedAgentClient(null, "report-client"))
                    .isInstanceOf(AgentClientStatusUnavailableException.class);
            assertThat(errors(logged)).as("a minute later, the outage is said again").hasSize(3);
        } finally {
            logger.detachAppender(logged);
            guard.destroy();
        }
    }

    /**
     * Reading a request is answered by the list in memory: the registry is not asked, whatever state it is in, and the
     * suspension is still read from the registry, so the failure of the registry never lifts it.
     */
    @Test
    void aRequestIsReadFromTheListAndASuspensionStillFromTheRegistry() {
        registry.register(new AgentRegistrationRequest(null, "report-bot", "Report bot", null, "report-client", "carol", null));
        AtomicBoolean failing = new AtomicBoolean();
        AtomicLong lookups = new AtomicLong();
        AgentRegistry counted = new InMemoryAgentRegistry() {
            @Override
            public Optional<AgentRegistration> findByClientId(String tenantId, String clientId) {
                lookups.incrementAndGet();
                if (failing.get()) {
                    throw new IllegalStateException("registry unavailable");
                }
                return registry.findByClientId(tenantId, clientId);
            }

            @Override
            public List<AgentRegistration> findAllByClientId(String clientId) {
                lookups.incrementAndGet();
                if (failing.get()) {
                    throw new IllegalStateException("registry unavailable");
                }
                return registry.findAllByClientId(clientId);
            }

            @Override
            public List<AgentApproval> approvals(int limit) {
                return registry.approvals(limit);
            }
        };
        ActiveAgentList list = new ActiveAgentList(counted);
        list.refresh();
        RegistryAgentClientDirectory withList = new RegistryAgentClientDirectory(counted, new RequestPathDatabaseGuard(), list);

        failing.set(true);
        assertThat(withList.requestPathActiveAgentForClient(null, "report-client")).contains("report-bot");
        assertThat(withList.requestPathActiveAgentForAccount(null, "report-bot")).contains("report-bot");
        assertThat(withList.requestPathActiveAgentForAccount(null, "alice")).isEmpty();
        assertThat(lookups.get()).as("the registry was not asked to read a request").isZero();

        assertThatThrownBy(() -> withList.suspendedAgentClient(null, "report-client"))
                .as("the suspension is read from the registry, and a failure does not read as not suspended")
                .isInstanceOf(AgentClientStatusUnavailableException.class);
        assertThatThrownBy(() -> withList.activeAgentForClient(null, "report-client"))
                .as("what decides something is asked of the registry")
                .isInstanceOf(AgentClientStatusUnavailableException.class);
        failing.set(false);

        registry.suspend(null, "report-bot", "stopped elsewhere");
        assertThat(withList.requestPathActiveAgentForClient(null, "report-client"))
                .as("a change no one told the list of shows when the list is read again")
                .contains("report-bot");
        assertThat(withList.suspendedAgentClient(null, "report-client")).as("the suspension is not late").isTrue();
        assertThat(withList.activeAgentForClient(null, "report-client")).isEmpty();
        list.refresh();
        assertThat(withList.requestPathActiveAgentForClient(null, "report-client")).isEmpty();
    }

    @Test
    void aDirectoryWithoutAListReadsARequestFromTheRegistry() {
        registry.register(new AgentRegistrationRequest(null, "report-bot", "Report bot", null, "report-client", "carol", null));

        assertThat(directory.requestPathActiveAgentForClient(null, "report-client")).contains("report-bot");
        assertThat(directory.requestPathActiveAgentForAccount(null, "alice")).isEmpty();
        assertThat(new RegistryAgentClientDirectory(null, new RequestPathDatabaseGuard(),
                new ActiveAgentList(registry)).requestPathActiveAgentForClient(null, "report-client")).isEmpty();
    }

    @Test
    void aListThatCannotBeReadMakesARequestUnreadableAndNeverNoAgent() {
        ActiveAgentList notRead = new ActiveAgentList(registry);
        RegistryAgentClientDirectory withList = new RegistryAgentClientDirectory(registry, new RequestPathDatabaseGuard(), notRead);

        assertThatThrownBy(() -> withList.requestPathActiveAgentForClient(null, "report-client"))
                .isInstanceOf(AgentClientStatusUnavailableException.class);
        assertThatThrownBy(() -> withList.requestPathActiveAgentForAccount(null, "alice"))
                .isInstanceOf(AgentClientStatusUnavailableException.class);
    }

    private static List<ILoggingEvent> errors(ListAppender<ILoggingEvent> logged) {
        return logged.list.stream().filter(event -> event.getLevel() == Level.ERROR).toList();
    }

    /** What the registry answers is unchanged while it answers: a suspension is found, a client not suspended is not. */
    @Test
    void aRegistryThatAnswersStillTellsSuspendedFromNot() {
        registry.register(new AgentRegistrationRequest(null, "report-bot", "Report bot", null, "report-client", "carol", null));
        registry.register(new AgentRegistrationRequest(null, "sync-bot", "Sync bot", null, "sync-client", "carol", null));
        registry.suspend(null, "sync-bot", "stopped");

        assertThat(directory.suspendedAgentClient(null, "report-client")).isFalse();
        assertThat(directory.suspendedAgentClient(null, "sync-client")).isTrue();
        assertThat(directory.suspendedAgentClient(null, "unknown-client")).isFalse();
        assertThat(new RegistryAgentClientDirectory(null).suspendedAgentClient(null, "report-client")).isFalse();
    }
}
