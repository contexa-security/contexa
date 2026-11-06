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
package io.contexa.contexacore.testsupport;

import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationAuthorizer;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationStore;
import io.contexa.contexacore.autonomous.agent.AgentNotice;
import io.contexa.contexacore.autonomous.agent.AgentNotices;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentNoticeStore;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What every store of the confirmations does when the first requests of one agent arrive together: the person is mailed
 * once and told of the others on the console. The in-memory store and the database store both run it, so that they
 * decide the same.
 */
public final class AgentConfirmationFirstRequestsContract {

    private static final String PERSON = "alice";

    private AgentConfirmationFirstRequestsContract() {
    }

    /**
     * Two first requests of one agent, each reading the agent's confirmations before either has saved its own (the
     * store lets both look together), mail the person once and leave the other on the console.
     */
    public static void twoFirstRequestsMailThePersonOnce(AgentConfirmationStore store) throws Exception {
        Console console = new Console(readingTogether(store, 2));

        console.requestTogether(agent("report-agent"), "hash-1", "hash-2");

        assertThat(console.mailed()).as("notices sent by mail").hasSize(1);
        assertThat(console.noticesOf("report-agent")).as("notices kept for the console").hasSize(2)
                .filteredOn(notice -> AgentNotice.CONSOLE.equals(notice.deliveredBy())).hasSize(1);
    }

    /**
     * Many first requests of many agents at once, with no help to make them meet: each agent mails the person once.
     */
    public static void manyAgentsMailThePersonOncePerAgent(AgentConfirmationStore store, int agents, int requestsEach)
            throws Exception {
        Console console = new Console(store);
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Boolean>> requests = new ArrayList<>();
            for (int agent = 0; agent < agents; agent++) {
                ZeroTrustSubject subject = agent("agent-" + agent);
                for (int request = 0; request < requestsEach; request++) {
                    String hash = "hash-" + agent + "-" + request;
                    Callable<Boolean> task = () -> {
                        go.await();
                        return console.service.request(console.ask(subject, hash)).isPresent();
                    };
                    requests.add(executor.submit(task));
                }
            }
            go.countDown();
            for (Future<Boolean> request : requests) {
                assertThat(request.get(60, TimeUnit.SECONDS)).isTrue();
            }
        } finally {
            executor.shutdownNow();
        }

        for (int agent = 0; agent < agents; agent++) {
            String agentId = "agent-" + agent;
            assertThat(console.noticesOf(agentId)).as("notices of %s", agentId).hasSize(requestsEach)
                    .filteredOn(notice -> !AgentNotice.CONSOLE.equals(notice.deliveredBy())).as("mailed for %s", agentId)
                    .hasSize(1);
        }
        assertThat(console.mailed()).hasSize(agents);
    }

    /**
     * A store that fails when it is asked to save and tell together still keeps the request: the confirmation is saved
     * once and the person is mailed, as when the waiting ones could not be read before.
     */
    public static void aRequestIsKeptAndMailedWhenTheStoreCannotTell(AgentConfirmationStore failingToTell)
            throws Exception {
        Console console = new Console(failingToTell);

        assertThat(console.service.request(console.ask(agent("report-agent"), "hash-1"))).isPresent();

        assertThat(failingToTell.forRecipient(PERSON, 10)).hasSize(1);
        assertThat(console.mailed()).hasSize(1);
        assertThat(console.noticesOf("report-agent")).hasSize(1);
    }

    /**
     * The store, as the service sees it, with the {@code waiting} reads of two callers held until both have asked: the way
     * two requests that arrive together look at the same state.
     */
    private static AgentConfirmationStore readingTogether(AgentConfirmationStore real, int parties) {
        CyclicBarrier barrier = new CyclicBarrier(parties);
        return (AgentConfirmationStore) Proxy.newProxyInstance(AgentConfirmationStore.class.getClassLoader(),
                new Class<?>[]{AgentConfirmationStore.class}, (proxy, method, args) -> {
                    Object result;
                    try {
                        result = method.invoke(real, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                    if (method.getName().equals("waiting")) {
                        try {
                            barrier.await(3, TimeUnit.SECONDS);
                        } catch (TimeoutException | BrokenBarrierException ignored) {
                            // the other request is not coming: it waits for the first one to finish
                        }
                    }
                    return result;
                });
    }

    private static ZeroTrustSubject agent(String agentId) {
        return new ZeroTrustSubject(null, PERSON, SubjectKind.DELEGATED_AGENT, agentId, "DLG-" + agentId);
    }

    /** The service on the store, with the person's channel and notices kept in memory. */
    private static final class Console {

        private final List<AgentNotice> mailed = Collections.synchronizedList(new ArrayList<>());
        private final InMemoryAgentNoticeStore notices = new InMemoryAgentNoticeStore();
        private final AgentConfirmationService service;

        Console(AgentConfirmationStore store) {
            AgentConfirmationAuthorizer authorizer = new AgentConfirmationAuthorizer() {
                @Override
                public String authorize(AgentConfirmation approved) {
                    return "authorization-" + approved.confirmationId();
                }

                @Override
                public boolean verify(AgentConfirmation approved) {
                    return true;
                }
            };
            AgentNotices agentNotices = new AgentNotices(notices, notice -> {
                mailed.add(notice);
                return "MAIL";
            });
            service = new AgentConfirmationService(store, authorizer, agentNotices, null, null, Duration.ofMinutes(15),
                    Clock.systemUTC());
        }

        AgentConfirmationService.ConfirmationRequest ask(ZeroTrustSubject subject, String hash) {
            return new AgentConfirmationService.ConfirmationRequest(subject, hash, "POST", "/api/export",
                    AgentConfirmation.DECISION_CHALLENGE, "Export outside the delegation", "req-" + hash,
                    "https://app.test");
        }

        void requestTogether(ZeroTrustSubject subject, String first, String second) throws Exception {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                CountDownLatch go = new CountDownLatch(1);
                List<Future<Boolean>> requests = new ArrayList<>();
                for (String hash : List.of(first, second)) {
                    Callable<Boolean> task = () -> {
                        go.await();
                        return service.request(ask(subject, hash)).isPresent();
                    };
                    requests.add(executor.submit(task));
                }
                go.countDown();
                for (Future<Boolean> request : requests) {
                    assertThat(request.get(60, TimeUnit.SECONDS)).isTrue();
                }
            } finally {
                executor.shutdownNow();
            }
        }

        List<AgentNotice> mailed() {
            return List.copyOf(mailed);
        }

        List<AgentNotice> noticesOf(String agentId) {
            return notices.forRecipient(PERSON, 1000).stream()
                    .filter(notice -> notice.kind().equals(AgentNotice.CONFIRMATION_REQUESTED)
                            && agentId.equals(notice.agentId()))
                    .toList();
        }
    }
}
