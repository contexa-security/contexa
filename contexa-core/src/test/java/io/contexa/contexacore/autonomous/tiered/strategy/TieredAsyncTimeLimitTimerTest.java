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
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.infra.ContexaReactorResources;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The asynchronous analyses of both layers end at their time limit on Contexa's own timer, with the same fallback decision as
 * before. Reactor measures a {@code timeout(Duration)} given no scheduler on its {@code parallel} scheduler, and the fallback is then
 * made on that thread, one the whole JVM shares.
 */
class TieredAsyncTimeLimitTimerTest {

    @Test
    void theFirstLayersAsyncAnalysisEndsAtItsLimitOnContexasTimer() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().getTimeout().setTotalMs(50);
        PipelineOrchestrator pipeline = slowPipeline();
        Layer1ContextualStrategy layer1 = new Layer1ContextualStrategy(null, null, new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties), null, null, null, null, null,
                null, new PromptContextAuthorizationService(), null, pipeline, properties);

        String[] madeOn = new String[1];
        SecurityDecision decision = layer1.analyzeWithContextAsync(event())
                .doOnNext(fallback -> madeOn[0] = Thread.currentThread().getName())
                .block(Duration.ofSeconds(10));

        assertThat(decision).isNotNull();
        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(madeOn[0]).startsWith("contexa-timer-");
    }

    /**
     * The second layer's analysis runs on the thread that subscribes, and {@code Mono.fromCallable} calls it when it is asked for
     * its value, which is before {@code timeout} has started its timer: the timer is started and cancelled once the analysis has
     * answered, and the analysis's own limit on the pipeline ends a slow one. The timer it starts is Contexa's.
     */
    @Test
    void theSecondLayersAsyncAnalysisStartsItsTimerOnContexasTimer() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer2().setTimeoutMs(50);
        PipelineOrchestrator pipeline = slowPipeline();
        Layer2ExpertStrategy layer2 = new Layer2ExpertStrategy(null, null, new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties), null, null, null, properties,
                null, null, null, null, new PromptContextAuthorizationService(), null, pipeline);

        noTimerThreadOfContexa();

        SecurityDecision decision = layer2.performDeepAnalysisAsync(event()).block(Duration.ofSeconds(10));

        // the decision is unchanged: the technical fallback of a pipeline that did not answer in time
        assertThat(decision).isNotNull();
        assertThat(decision.getAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
        // a worker of a timer starts its thread with its first task: the timer started here was Contexa's
        assertThat(timerThreadsOfContexa()).isNotEmpty();
    }

    /** Contexa's timer as a new one with no thread yet: the last holder lets go and the threads end. */
    static void noTimerThreadOfContexa() {
        ContexaReactorResources.hold().close();
        long until = System.currentTimeMillis() + 10_000L;
        while (!timerThreadsOfContexa().isEmpty() && System.currentTimeMillis() < until) {
            Thread.onSpinWait();
        }
        assertThat(timerThreadsOfContexa()).isEmpty();
    }

    static List<String> timerThreadsOfContexa() {
        return Thread.getAllStackTraces().keySet().stream().filter(Thread::isAlive).map(Thread::getName)
                .filter(name -> name.startsWith("contexa-timer-")).toList();
    }

    /** A pipeline that takes far longer than the limits above to say nothing. */
    private static PipelineOrchestrator slowPipeline() {
        PipelineOrchestrator pipeline = mock(PipelineOrchestrator.class);
        when(pipeline.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenAnswer(invocation -> {
                    Thread.sleep(500);
                    return Mono.never();
                });
        return pipeline;
    }

    private static SecurityEvent event() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("httpMethod", "POST");
        metadata.put("requestPath", "/api/admin/config");
        return SecurityEvent.builder()
                .eventId("async-time-limit")
                .userId("user-003")
                .sessionId("session-003")
                .sourceIp("10.0.0.51")
                .userAgent("Mozilla/5.0")
                .timestamp(Instant.now())
                .metadata(metadata)
                .build();
    }
}
