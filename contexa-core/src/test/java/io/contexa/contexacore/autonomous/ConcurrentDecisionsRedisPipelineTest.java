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
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter.PersistedFinalDecision;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * PR-72: a user's calls at one moment on the distributed stores, through the agent, the enforcement and the real Redis.
 * A later decision of the same user is no failure of an earlier one; the request that made it goes on.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_BACKLOG_REDIS_PORT", matches = "[0-9]+")
class ConcurrentDecisionsRedisPipelineTest {

    private static final int CALLS_AT_ONCE = 8;
    private static final int ROUNDS = 50;

    private static LettuceConnectionFactory factory;
    private static RedisTemplate<String, Object> objects;
    private static StringRedisTemplate strings;
    private static ZeroTrustActionRedisRepository actions;

    @BeforeAll
    static void connect() {
        factory = new LettuceConnectionFactory("127.0.0.1", Integer.parseInt(System.getenv("CONTEXA_BACKLOG_REDIS_PORT")));
        factory.afterPropertiesSet();
        objects = RedisTestTemplates.newProductionAlignedRedisTemplate(factory);
        strings = RedisTestTemplates.newStringRedisTemplate(factory);
        actions = new ZeroTrustActionRedisRepository(objects, strings);
    }

    @AfterAll
    static void close() {
        if (factory != null) {
            factory.destroy();
        }
    }

    @Test
    void callsOfOneUserAtOnceAreAllDecided() throws Exception {
        Pipeline pipeline = new Pipeline();
        List<Throwable> failures = new ArrayList<>();
        for (int round = 0; round < ROUNDS; round++) {
            String user = user();
            failures.addAll(pipeline.processAtOnce(user, Collections.nCopies(CALLS_AT_ONCE, "ALLOW")));
            assertThat(actions.getActionFromHash(user)).isEqualTo(ZeroTrustAction.ALLOW);
            actions.removeAllUserData(user);
        }

        assertThat(failures).as("%d of %d calls failed", failures.size(), CALLS_AT_ONCE * ROUNDS).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"CHALLENGE", "ESCALATE", "BLOCK"})
    void aRestrictionAmongCallsAtOnceIsTheOneInForceAndNoCallFails(String restriction) throws Exception {
        Pipeline pipeline = new Pipeline();
        List<String> decisions = new ArrayList<>(Collections.nCopies(CALLS_AT_ONCE - 1, "ALLOW"));
        decisions.add(CALLS_AT_ONCE / 2, restriction);
        List<Throwable> failures = new ArrayList<>();
        for (int round = 0; round < ROUNDS; round++) {
            String user = user();
            failures.addAll(pipeline.processAtOnce(user, decisions));
            assertThat(actions.getActionFromHash(user)).as("round %d", round)
                    .isEqualTo(ZeroTrustAction.valueOf(restriction));
            assertThat(actions.getCurrentAction(user)).as("round %d", round)
                    .isEqualTo(ZeroTrustAction.valueOf(restriction));
            actions.removeAllUserData(user);
        }

        assertThat(failures).as("%d of %d calls failed", failures.size(), CALLS_AT_ONCE * ROUNDS).isEmpty();
    }

    /** A retry that restores its persisted decision while the user's next decisions land keeps its idempotency. */
    @Test
    void restoringAPersistedDecisionAmongCallsAtOnceDoesNotFail() throws Exception {
        Pipeline pipeline = new Pipeline();
        pipeline.persisted = true;
        List<Throwable> failures = new ArrayList<>();
        for (int round = 0; round < ROUNDS; round++) {
            String user = user();
            failures.addAll(pipeline.processAtOnce(user, Collections.nCopies(CALLS_AT_ONCE, "ALLOW")));
            actions.removeAllUserData(user);
        }

        assertThat(failures).as("%d of %d calls failed", failures.size(), CALLS_AT_ONCE * ROUNDS).isEmpty();
        assertThat(pipeline.analysed).as("each call restored its decision instead of asking again").isEmpty();
    }

    private static String user() {
        return "pipeline-" + UUID.randomUUID();
    }

    private static final class Pipeline {

        final Map<String, String> decisionOfEvent = new ConcurrentHashMap<>();
        final Map<String, Boolean> analysed = new ConcurrentHashMap<>();
        volatile boolean persisted;
        private final SecurityPlaneAgent agent;

        Pipeline() {
            RedisSecurityContextDataStore store = new RedisSecurityContextDataStore(objects);
            SecurityZeroTrustProperties mode = new SecurityZeroTrustProperties();
            mode.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            AiSecurityDecisionObservationWriter writer = mock(AiSecurityDecisionObservationWriter.class);
            when(writer.recordDecision(any(), any(), any())).thenAnswer(call -> UUID.randomUUID().toString());
            when(writer.findFinalDecision(anyString())).thenAnswer(call -> persisted
                    ? new PersistedFinalDecision(UUID.randomUUID().toString(), null, null, "ALLOW", null,
                    UUID.randomUUID().toString(), null, null, null, "persisted")
                    : null);
            SecurityDecisionEnforcementHandler enforcement = new SecurityDecisionEnforcementHandler(actions, null,
                    mock(IBlockedUserRecorder.class), new InMemoryBlockingSignalBroadcaster(), mode, Runnable::run,
                    () -> writer, store);
            SecurityEventHandler analysis = mock(SecurityEventHandler.class);
            when(analysis.getOrder()).thenReturn(0);
            when(analysis.getName()).thenReturn("ControlledAnalysis");
            when(analysis.canHandle(any())).thenReturn(true);
            when(analysis.handle(any())).thenAnswer(call -> {
                SecurityEventContext context = call.getArgument(0);
                String eventId = context.getSecurityEvent().getEventId();
                analysed.put(eventId, Boolean.TRUE);
                context.addMetadata("processingResult", ProcessingResult.builder().success(true)
                        .action(decisionOfEvent.get(eventId)).reasoning("Controlled decision").build());
                return true;
            });
            SecurityPlaneProperties properties = new SecurityPlaneProperties();
            properties.getAgent().setAutoStart(false);
            agent = new SecurityPlaneAgent(mock(SecurityMonitoringService.class), store, null,
                    new SecurityEventProcessor(List.of(analysis, enforcement), "pipeline-test"), properties, Runnable::run);
            agent.setZeroTrustActionRepository(actions);
            agent.setAiSecurityDecisionObservationWriterSupplier(() -> writer);
            agent.setDecisionEnforcementHandlerSupplier(() -> enforcement);
        }

        /** Each call in a thread of its own, all released at once; what failed, as the request would see it. */
        List<Throwable> processAtOnce(String user, List<String> decisions) throws Exception {
            ExecutorService pool = Executors.newFixedThreadPool(decisions.size());
            try {
                CyclicBarrier start = new CyclicBarrier(decisions.size());
                List<Future<?>> calls = new ArrayList<>();
                for (String decision : decisions) {
                    SecurityEvent event = event(user);
                    decisionOfEvent.put(event.getEventId(), decision);
                    calls.add(pool.submit(() -> {
                        start.await();
                        return agent.processSecurityEvent(event);
                    }));
                }
                List<Throwable> failures = new ArrayList<>();
                for (Future<?> call : calls) {
                    try {
                        call.get(30, TimeUnit.SECONDS);
                    } catch (ExecutionException failure) {
                        failures.add(failure.getCause());
                    }
                }
                return failures;
            } finally {
                pool.shutdownNow();
            }
        }

        private static SecurityEvent event(String user) {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("requestPath", "/orders");
            metadata.put("httpMethod", "GET");
            return SecurityEvent.builder().eventId(UUID.randomUUID().toString()).userId(user)
                    .sessionId("session-" + user).sourceIp("127.0.0.1").userAgent("pipeline-test")
                    .metadata(metadata).build();
        }
    }
}
