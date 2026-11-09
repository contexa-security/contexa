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
package io.contexa.contexacore.std.operations;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacore.exception.StrategicOperationConflictException;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.lock.InMemoryDistributedLockService;
import io.contexa.contexacore.std.components.event.AuditLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The strategic lock against a real lock service: an identical request that is still running refuses the next one, whichever
 * processor, node name or subscription it comes through, and every way an operation ends gives its lock back.
 */
class AINativeProcessorStrategicLockTest {

    private static final Duration WAIT = Duration.ofSeconds(3);
    private static final String SHARED_NODE_NAME = "SecurityPlaneAgent-1";

    private AuditLogger auditLogger;
    private DistributedLockService locks;
    private DistributedStrategyExecutor<TestContext> executor;
    private AINativeProcessor<TestContext> processor;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        auditLogger = mock(AuditLogger.class);
        locks = new InMemoryDistributedLockService();
        executor = mock(DistributedStrategyExecutor.class);
        when(auditLogger.startAudit(any())).thenReturn("audit");
        processor = new AINativeProcessor<>(auditLogger, locks, executor, SHARED_NODE_NAME);
    }

    @Test
    void anIdenticalRequestThatIsRunningIsRefused() {
        AIRequest<TestContext> request = request("summarize risk");
        Sinks.One<TestResponse> running = Sinks.one();
        when(executor.executeDistributedStrategyAsync(request, TestResponse.class)).thenReturn(running.asMono());
        Disposable first = processor.process(request, TestResponse.class).subscribe();

        assertThatThrownBy(() -> processor.process(request, TestResponse.class).block(WAIT))
                .isInstanceOf(StrategicOperationConflictException.class)
                .hasMessageStartingWith("Strategic operation conflict: ");

        running.tryEmitValue(new TestResponse());
        assertThat(first.isDisposed()).isTrue();
    }

    @Test
    void theSameRequestRunsAgainOnceTheFirstHasEnded() {
        AIRequest<TestContext> request = request("summarize risk");
        when(executor.executeDistributedStrategyAsync(request, TestResponse.class)).thenReturn(Mono.just(new TestResponse()));

        assertThat(processor.process(request, TestResponse.class).block(WAIT)).isNotNull();
        assertThat(processor.process(request, TestResponse.class).block(WAIT)).isNotNull();
    }

    @Test
    void aDifferentRequestIsNotRefused() {
        AIRequest<TestContext> running = request("summarize risk");
        AIRequest<TestContext> other = request("list the open settlements");
        Sinks.One<TestResponse> held = Sinks.one();
        when(executor.executeDistributedStrategyAsync(running, TestResponse.class)).thenReturn(held.asMono());
        when(executor.executeDistributedStrategyAsync(other, TestResponse.class)).thenReturn(Mono.just(new TestResponse()));
        processor.process(running, TestResponse.class).subscribe();

        assertThat(processor.process(other, TestResponse.class).block(WAIT)).isNotNull();

        held.tryEmitValue(new TestResponse());
    }

    @Test
    void anOperationThatFailsGivesItsLockBack() {
        AIRequest<TestContext> request = request("summarize risk");
        IllegalStateException failure = new IllegalStateException("model unavailable");
        when(executor.executeDistributedStrategyAsync(request, TestResponse.class))
                .thenReturn(Mono.error(failure), Mono.just(new TestResponse()));

        assertThatThrownBy(() -> processor.process(request, TestResponse.class).block(WAIT)).isSameAs(failure);

        assertThat(processor.process(request, TestResponse.class).block(WAIT)).isNotNull();
    }

    @Test
    void anOperationThatIsCancelledGivesItsLockBack() {
        AIRequest<TestContext> request = request("summarize risk");
        Sinks.One<TestResponse> never = Sinks.one();
        when(executor.executeDistributedStrategyAsync(request, TestResponse.class))
                .thenReturn(never.asMono(), Mono.just(new TestResponse()));
        Disposable first = processor.process(request, TestResponse.class).subscribe();
        first.dispose();

        assertThat(processor.process(request, TestResponse.class).block(WAIT)).isNotNull();
    }

    /** The default node name is the same on every node, so the lock cannot tell requests apart by it. */
    @Test
    void processorsThatShareANodeNameStillRefuseEachOther() {
        AINativeProcessor<TestContext> otherNode = new AINativeProcessor<>(auditLogger, locks, executor, SHARED_NODE_NAME);
        AIRequest<TestContext> request = request("summarize risk");
        Sinks.One<TestResponse> running = Sinks.one();
        when(executor.executeDistributedStrategyAsync(request, TestResponse.class)).thenReturn(running.asMono());
        processor.process(request, TestResponse.class).subscribe();

        assertThatThrownBy(() -> otherNode.process(request, TestResponse.class).block(WAIT))
                .isInstanceOf(StrategicOperationConflictException.class);

        running.tryEmitValue(new TestResponse());
    }

    /** A Mono is cold: each subscription is one run, so two subscriptions at once are two runs of the same request. */
    @Test
    void oneMonoSubscribedTwiceAtOnceIsRefusedTheSecondTime() {
        AIRequest<TestContext> request = request("summarize risk");
        Sinks.One<TestResponse> running = Sinks.one();
        when(executor.executeDistributedStrategyAsync(request, TestResponse.class)).thenReturn(running.asMono());
        Mono<TestResponse> once = processor.process(request, TestResponse.class);
        once.subscribe();

        assertThatThrownBy(() -> once.block(WAIT)).isInstanceOf(StrategicOperationConflictException.class);

        running.tryEmitValue(new TestResponse());
    }

    @Test
    void aStreamThatIsRunningRefusesAnIdenticalStream() {
        AIRequest<TestContext> request = request("summarize risk");
        Sinks.Many<String> running = Sinks.many().unicast().onBackpressureBuffer();
        when(executor.executeDistributedStrategyStream(any(), any(), any())).thenReturn(running.asFlux());
        processor.processStream(request).subscribe();

        assertThatThrownBy(() -> processor.processStream(request).collectList().block(WAIT))
                .isInstanceOf(StrategicOperationConflictException.class)
                .hasMessageStartingWith("Strategic streaming operation conflict: ");

        running.tryEmitComplete();
    }

    @Test
    void aStreamGivesItsLockBackWhenItEnds() {
        AIRequest<TestContext> request = request("summarize risk");
        when(executor.executeDistributedStrategyStream(any(), any(), any()))
                .thenReturn(Flux.just("one", "two"), Flux.just("three"));

        assertThat(processor.processStream(request).collectList().block(WAIT)).containsExactly("one", "two");
        assertThat(processor.processStream(request).collectList().block(WAIT)).containsExactly("three");
    }

    /** A lock store that cannot answer is no conflict: it must not be reported as one, and nothing runs without the lock. */
    @Test
    void aLockStoreThatFailsIsNotReportedAsAConflict() {
        DistributedLockService broken = mock(DistributedLockService.class);
        when(broken.tryLock(any(), any(), any(Duration.class))).thenThrow(new IllegalStateException("redis is down"));
        AINativeProcessor<TestContext> unlocked = new AINativeProcessor<>(auditLogger, broken, executor, SHARED_NODE_NAME);
        AIRequest<TestContext> request = request("summarize risk");

        assertThatThrownBy(() -> unlocked.process(request, TestResponse.class).block(WAIT))
                .isInstanceOf(AIOperationException.class)
                .isNotInstanceOf(StrategicOperationConflictException.class)
                .hasMessageStartingWith("Strategic lock unavailable: ")
                .hasRootCauseMessage("redis is down");
        assertThatThrownBy(() -> unlocked.processStream(request).collectList().block(WAIT))
                .isInstanceOf(AIOperationException.class)
                .isNotInstanceOf(StrategicOperationConflictException.class)
                .hasMessageStartingWith("Strategic lock unavailable: ");

        verify(executor, never()).executeDistributedStrategyAsync(any(), any());
        verify(executor, never()).executeDistributedStrategyStream(any(), any(), any());
    }

    private static AIRequest<TestContext> request(String query) {
        AIRequest<TestContext> request = new AIRequest<>(
                new TestContext("user-1", "session-1", "tenant-a"),
                new TemplateType("standard"),
                new DiagnosisType("general"));
        request.setNaturalLanguageQuery(query);
        request.withParameter("purpose", "security");
        return request;
    }

    private static final class TestContext extends DomainContext {
        private TestContext(String userId, String sessionId, String organizationId) {
            setUserId(userId);
            setSessionId(sessionId);
            setOrganizationId(organizationId);
        }

        @Override
        public String getDomainType() {
            return "test";
        }
    }

    private static final class TestResponse extends AIResponse {
    }
}
