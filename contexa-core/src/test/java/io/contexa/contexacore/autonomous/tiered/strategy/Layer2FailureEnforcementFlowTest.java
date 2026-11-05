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
package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import io.contexa.contexacore.testsupport.AdjustableClock;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PR-83, as measured on the real server (M20): Layer1 hands the request over and only Layer2 fails. The request goes
 * through the real Layer2, the real cold path, the real enforcement and both real repositories: the user ends under the
 * fallback action, never under an ESCALATE, and no time passing turns it into a BLOCK. With
 * allow-escalate-final-action on the request is held as before.
 */
class Layer2FailureEnforcementFlowTest {

    private static final String REDIS_PORT = "CONTEXA_BACKLOG_REDIS_PORT";

    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate strings;

    private final PipelineOrchestrator pipelineOrchestrator = mock(PipelineOrchestrator.class);
    private final IBlockedUserRecorder blockedUserRecorder = mock(IBlockedUserRecorder.class);
    private final BlockingSignalBroadcaster broadcaster = mock(BlockingSignalBroadcaster.class);
    private final AdjustableClock clock = new AdjustableClock();

    @BeforeAll
    static void connect() {
        String port = System.getenv(REDIS_PORT);
        if (port == null || !port.matches("[0-9]+")) {
            return;
        }
        factory = new LettuceConnectionFactory("127.0.0.1", Integer.parseInt(port));
        factory.afterPropertiesSet();
        strings = RedisTestTemplates.newStringRedisTemplate(factory);
    }

    @AfterAll
    static void close() {
        if (factory != null) {
            factory.destroy();
        }
    }

    private ZeroTrustActionRepository inMemory() {
        return new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
    }

    private static ZeroTrustActionRepository redis() {
        return new ZeroTrustActionRedisRepository(RedisTestTemplates.newProductionAlignedRedisTemplate(factory), strings);
    }

    private void failingModel() {
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.error(new IllegalStateException("HTTP 500 from the model server")));
    }

    private void hangingModel() {
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class))).thenReturn(Mono.never());
    }

    @Test
    void inMemoryAFailedSecondLayerEndsAsTheFallback() {
        failingModel();
        assertEndsAsTheFallback(inMemory(), layer1(true, false), new TieredStrategyProperties());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAFailedSecondLayerEndsAsTheFallback() {
        failingModel();
        assertEndsAsTheFallback(redis(), layer1(true, false), new TieredStrategyProperties());
    }

    @Test
    void inMemoryASecondLayerPastItsTimeEndsAsTheFallback() {
        hangingModel();
        assertEndsAsTheFallback(inMemory(), layer1(true, false), withTimeout(new TieredStrategyProperties()));
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisASecondLayerPastItsTimeEndsAsTheFallback() {
        hangingModel();
        assertEndsAsTheFallback(redis(), layer1(true, false), withTimeout(new TieredStrategyProperties()));
    }

    /** The first layer's own failure hands the request over too (TECHNICAL_FALLBACK_ESCALATE). */
    @Test
    void inMemoryBothLayersFailingEndAsTheFallback() {
        failingModel();
        assertEndsAsTheFallback(inMemory(), layer1(false, true), new TieredStrategyProperties());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisBothLayersFailingEndAsTheFallback() {
        failingModel();
        assertEndsAsTheFallback(redis(), layer1(false, true), new TieredStrategyProperties());
    }

    private void assertEndsAsTheFallback(ZeroTrustActionRepository repository, Layer1ContextualStrategy layer1,
                                         TieredStrategyProperties properties) {
        repository.setEscalateTerminalAction(properties.getLayer2().escalateTerminalAction());
        String user = "pr83-flow-" + UUID.randomUUID();
        SecurityEvent event = event(user);

        ProcessingResult result = decide(repository, layer1, properties, event);

        assertThat(result.getProposedAction()).isEqualTo("ESCALATE");
        assertThat(result.getAction()).isEqualTo("CHALLENGE");
        assertThat(result.getLlmDecisionPresent()).isFalse();
        assertThat(result.getTechnicalFallbackApplied()).isTrue();
        assertThat(repository.getCurrentAction(user, "context-1")).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getLastVerifiedAction(user)).isEqualTo(ZeroTrustAction.CHALLENGE);

        // The five minutes after which an ESCALATE was promoted pass: the CHALLENGE stands, nothing is blocked.
        passTime(repository, user, ZeroTrustAction.ESCALATE.getDefaultTtl().plusSeconds(1));

        assertThat(repository.getCurrentAction(user, "context-1")).isEqualTo(ZeroTrustAction.CHALLENGE);
        verify(blockedUserRecorder, never()).recordBlock(any(), anyString(), any(), any(), any(), any(), any());
        repository.removeAllUserData(user);
    }

    /** allow-escalate-final-action keeps the hold of a failed second layer and leaves the promotion to the filter. */
    @Test
    void inMemoryAnAllowedFinalEscalateStaysEscalate() {
        failingModel();
        assertStaysEscalate(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAnAllowedFinalEscalateStaysEscalate() {
        failingModel();
        assertStaysEscalate(redis());
    }

    private void assertStaysEscalate(ZeroTrustActionRepository repository) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setAllowEscalateFinalAction(true);
        repository.setEscalateTerminalAction(properties.getLayer2().escalateTerminalAction());
        String user = "pr83-flow-" + UUID.randomUUID();

        ProcessingResult result = decide(repository, layer1(true, false), properties, event(user));

        assertThat(result.getAction()).isEqualTo("ESCALATE");
        assertThat(repository.getCurrentAction(user, "context-1")).isEqualTo(ZeroTrustAction.ESCALATE);
        passTime(repository, user, ZeroTrustAction.ESCALATE.getDefaultTtl().plusSeconds(1));
        assertThat(repository.getCurrentAction(user, "context-1")).isEqualTo(ZeroTrustAction.ESCALATE);
        repository.removeAllUserData(user);
    }

    /** A model that answers keeps its answer: this path of the fix touches failures only. */
    @Test
    void inMemoryAModelsBlockStays() {
        SecurityDecisionResponse block = new SecurityDecisionResponse();
        block.setAction("BLOCK");
        block.setReasoning("The export is outside the owner's work.");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class),
                eq(SecurityDecisionResponse.class))).thenReturn(Mono.just(block));
        ZeroTrustActionRepository repository = inMemory();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        repository.setEscalateTerminalAction(properties.getLayer2().escalateTerminalAction());
        String user = "pr83-flow-" + UUID.randomUUID();

        ProcessingResult result = decide(repository, layer1(true, false), properties, event(user));

        assertThat(result.getAction()).isEqualTo("BLOCK");
        assertThat(repository.getCurrentAction(user, "context-1")).isEqualTo(ZeroTrustAction.BLOCK);
    }

    private ProcessingResult decide(ZeroTrustActionRepository repository, Layer1ContextualStrategy layer1,
                                    TieredStrategyProperties properties, SecurityEvent event) {
        Layer2ExpertStrategy layer2 = new Layer2ExpertStrategy(null, null, new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                null, null, null, properties, null, null, null, null,
                new PromptContextAuthorizationService(), null, pipelineOrchestrator);
        ColdPathEventProcessor coldPath = new ColdPathEventProcessor(layer1, layer2, mock(LlmAnalysisEventListener.class));

        ProcessingResult result = coldPath.processEvent(event, 0.5);

        AiSecurityDecisionObservationWriter observations = mock(AiSecurityDecisionObservationWriter.class);
        when(observations.recordDecision(any(), any(), any())).thenReturn("observation-" + UUID.randomUUID());
        when(observations.isStoreConfigured()).thenReturn(true);
        // A final decision is written for the processing that owns the event, as the security plane marks it.
        SecurityContextDataStore ownership = mock(SecurityContextDataStore.class);
        when(ownership.isEventProcessingOwner(anyString(), anyString())).thenReturn(true);
        SecurityDecisionEnforcementHandler handler = new SecurityDecisionEnforcementHandler(repository,
                mock(SecurityLearningService.class), blockedUserRecorder, broadcaster, null, Runnable::run,
                () -> observations, ownership);
        handler.setEscalateTerminalAction(properties.getLayer2().escalateTerminalAction());
        SecurityEventContext context = SecurityEventContext.builder().securityEvent(event).build();
        context.addMetadata("processingResult", result);
        assertThat(handler.handle(context)).isTrue();
        return result;
    }

    /** Time passes for the store: the in-memory clock moves, a Redis key loses as much of its TTL. */
    private void passTime(ZeroTrustActionRepository repository, String user, Duration amount) {
        if (repository instanceof InMemoryZeroTrustActionRepository) {
            clock.advance(amount);
            return;
        }
        String key = ZeroTrustRedisKeys.autonomousActionAnalysis(user);
        Long remaining = strings.getExpire(key);
        if (remaining == null || remaining <= amount.toSeconds()) {
            strings.expire(key, Duration.ofMillis(200));
            Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> !Boolean.TRUE.equals(strings.hasKey(key)));
            return;
        }
        strings.expire(key, Duration.ofSeconds(remaining - amount.toSeconds()));
    }

    private static TieredStrategyProperties withTimeout(TieredStrategyProperties properties) {
        properties.getLayer2().setTimeoutMs(50);
        return properties;
    }

    private static Layer1ContextualStrategy layer1(boolean modelDecided, boolean technicalFallback) {
        Layer1ContextualStrategy layer1 = mock(Layer1ContextualStrategy.class);
        when(layer1.evaluate(any(SecurityEvent.class))).thenReturn(ThreatAssessment.builder()
                .strategyName("Layer1-Contextual")
                .action(ZeroTrustAction.ESCALATE.name())
                .autonomousAction(ZeroTrustAction.ESCALATE.name())
                .shouldEscalate(true)
                .llmDecisionPresent(modelDecided)
                .technicalFallbackApplied(technicalFallback)
                .reasoning("The facts conflict.")
                .build());
        return layer1;
    }

    private static SecurityEvent event(String user) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("requestId", "request-" + UUID.randomUUID());
        metadata.put("requestPath", "/owners");
        metadata.put("contextBindingHash", "context-1");
        metadata.put(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY, "identity-" + UUID.randomUUID());
        metadata.put(SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN, "owner-" + UUID.randomUUID());
        return SecurityEvent.builder().eventId("event-" + UUID.randomUUID()).userId(user).sessionId("session-1")
                .sourceIp("10.0.0.9").userAgent("TestAgent").metadata(metadata).build();
    }
}
