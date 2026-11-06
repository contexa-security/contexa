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
package io.contexa.contexacore.autonomous;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.event.listener.InMemorySecurityEventCollector;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Q-5 (PR-50), the whole way: the real queue, agent, enforcement and store, with only the model replaced. A model that
 * failed and came back frees the user with no step of theirs; what it decides then stands, whatever it is.
 */
@Timeout(value = 30, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class TechnicalChallengeRecoveryTest {

    private static final String USER = "alice";
    private static final String CONTEXT = "context-a";

    /** What the model answers now; null is a failure. */
    private final AtomicReference<String> model = new AtomicReference<>();
    private final List<String> analysed = new CopyOnWriteArrayList<>();
    private final InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository();
    private final InMemorySecurityContextDataStore dataStore = new InMemorySecurityContextDataStore();
    private final InMemorySecurityEventCollector collector = new InMemorySecurityEventCollector();
    private final ExecutorService analysisThreads = Executors.newFixedThreadPool(2);
    private SecurityMonitoringService monitor;
    private SecurityPlaneAgent agent;

    /** The analysis: the failure ends as what the layers make of a model that gave no answer. */
    private final SecurityEventHandler analysis = new SecurityEventHandler() {
        @Override
        public boolean handle(SecurityEventContext context) {
            analysed.add(context.getSecurityEvent().getEventId());
            String answer = model.get();
            context.addMetadata("processingResult", ProcessingResult.builder().success(true)
                    .action(answer != null ? answer : "CHALLENGE")
                    .llmDecisionPresent(answer != null)
                    .technicalFallbackApplied(answer == null)
                    .build());
            return true;
        }

        @Override
        public String getName() {
            return "analysis";
        }

        @Override
        public int getOrder() {
            return 50;
        }
    };

    @BeforeEach
    void setUp() {
        AiSecurityDecisionObservationWriter writer = mock(AiSecurityDecisionObservationWriter.class);
        when(writer.recordDecision(any(), any(), any())).thenAnswer(call -> UUID.randomUUID().toString());
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        SecurityDecisionEnforcementHandler enforcement = new SecurityDecisionEnforcementHandler(repository,
                mock(SecurityLearningService.class), mock(IBlockedUserRecorder.class), null, null, Runnable::run,
                () -> writer, dataStore);
        monitor = new SecurityMonitoringService(collector, properties);
        monitor.initialize();
        agent = new SecurityPlaneAgent(monitor, dataStore, mock(CentralAuditFacade.class),
                new SecurityEventProcessor(List.of(analysis, enforcement)), properties, analysisThreads);
        agent.setZeroTrustActionRepository(repository);
        agent.setJudgeAgainInterval(Duration.ofMillis(100));
        agent.initialize();
        agent.start();
    }

    @AfterEach
    void tearDown() {
        agent.shutdown();
        monitor.shutdown();
        analysisThreads.shutdownNow();
    }

    private void aRequest() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("zerotrust.category", "AUTHORIZATION");
        metadata.put("contextBindingHash", CONTEXT);
        metadata.put("requestId", "request-1");
        collector.dispatchEvent(SecurityEvent.builder().eventId("event-1").userId(USER).sessionId("session-1")
                .sourceIp("10.0.0.1").metadata(metadata).build());
    }

    private void theFailedAnalysisLeftItsChallenge() {
        Awaitility.await().untilAsserted(() -> {
            assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
            assertThat(repository.isTechnicalChallenge(USER)).isTrue();
        });
    }

    @Test
    void aModelThatIsBackFreesTheUser() {
        aRequest();
        theFailedAnalysisLeftItsChallenge();

        model.set("ALLOW");

        Awaitility.await().untilAsserted(() ->
                assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.ALLOW));
        assertThat(repository.isTechnicalChallenge(USER)).isFalse();
    }

    @Test
    void aModelThatIsBackAndDecidesToChallengeIsNotShortened() {
        aRequest();
        theFailedAnalysisLeftItsChallenge();

        model.set("CHALLENGE");

        Awaitility.await().untilAsserted(() -> assertThat(repository.isTechnicalChallenge(USER)).isFalse());
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    void aModelThatIsBackAndBlocksStopsTheUser() {
        aRequest();
        theFailedAnalysisLeftItsChallenge();

        model.set("BLOCK");

        Awaitility.await().untilAsserted(() ->
                assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK));
    }

    @Test
    void aModelThatStaysDownIsAskedAFewTimesAndNoMore() throws Exception {
        aRequest();

        int expected = 1 + SecurityPlaneAgent.JUDGE_AGAIN_TIMES;
        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(expected));
        Thread.sleep(400);

        assertThat(analysed).hasSize(expected);
        assertThat(new ArrayList<>(analysed)).doesNotHaveDuplicates();
        assertThat(repository.isTechnicalChallenge(USER)).isTrue();
    }

    @Test
    void aDecisionOfTheModelEndsTheQuestions() throws Exception {
        model.set("ALLOW");
        aRequest();
        Awaitility.await().untilAsserted(() ->
                assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.ALLOW));

        Thread.sleep(300);

        assertThat(analysed).hasSize(1);
    }
}
