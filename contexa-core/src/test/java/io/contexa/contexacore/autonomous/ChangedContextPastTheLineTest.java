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
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService.AsyncProtectableGate;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The line of analyses and a request of a changed context, with the agent itself: a full line leaves events unanalysed,
 * and the request of a changed context does not wait for a verdict (680d18171: a call is answered at once and the verdict
 * applies from the next request), so a full line, or no room for its analysis, holds it back no more than any other. The
 * rule of a request without a verdict stands: a general resource goes on, and a sensitive one is not let out before a
 * verdict: from a changed context it is told to come back at once, and the analysis of its context is started.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class ChangedContextPastTheLineTest {

    private static final String USER = "alice";
    private static final String HOME = "context-home";
    private static final String ELSEWHERE = "context-elsewhere";

    private final InMemoryZeroTrustActionRepository repository =
            new InMemoryZeroTrustActionRepository(Duration.ofHours(24));
    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final ZeroTrustEventListener listener = new ZeroTrustEventListener(mock(SecurityEventPublisher.class),
            repository, new SecurityZeroTrustProperties());
    private final SecurityMonitoringService monitor = mock(SecurityMonitoringService.class);
    private final SecurityEventProcessor processor = mock(SecurityEventProcessor.class);
    private final ExecutorService threads = Executors.newCachedThreadPool();
    private final AtomicBoolean noRoom = new AtomicBoolean();
    private final CountDownLatch release = new CountDownLatch(1);
    private final AtomicInteger asked = new AtomicInteger();
    private final AtomicInteger leftOut = new AtomicInteger();
    private final MethodInvocation invocation = mock(MethodInvocation.class);
    private final Authentication alice = new UsernamePasswordAuthenticationToken(USER, "n/a");
    private volatile Map<String, Object> request;
    private SecurityMonitoringService.SecurityEventBatchProcessor batches;
    private SecurityPlaneAgent agent;
    private SynchronousProtectableDecisionService service;

    @BeforeEach
    void setUp() {
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> {
            SecurityEvent event = call.getArgument(0);
            if (!USER.equals(event.getUserId())) {
                release.await();
                return analysed(event, ZeroTrustAction.ALLOW);
            }
            asked.incrementAndGet();
            repository.writeFinalAction(USER, ZeroTrustAction.BLOCK, Map.of("observationId", "observation-1",
                    "processingGeneration", "1", "contextBindingHash", ELSEWHERE));
            return analysed(event, ZeroTrustAction.BLOCK);
        });
        agent = new SecurityPlaneAgent(monitor, new InMemorySecurityContextDataStore(), mock(CentralAuditFacade.class),
                processor, new SecurityPlaneProperties(), task -> {
            if (noRoom.get()) {
                throw new RejectedExecutionException("no room");
            }
            threads.execute(task);
        });
        agent.initialize();
        agent.start();
        agent.setQueuedEventRecheck(new SecurityPlaneAgent.QueuedEventRecheck() {
            @Override
            public boolean answeredWithoutAnalysis(SecurityEvent event) {
                return false;
            }

            @Override
            public void leftOut(SecurityEvent event) {
                leftOut.incrementAndGet();
            }
        });
        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> captor =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(monitor).setBatchProcessor(captor.capture());
        batches = captor.getValue();
        service = new SynchronousProtectableDecisionService(publisher, listener, agent, repository);
        service.setDecisionWait(Duration.ofSeconds(5));
        when(publisher.buildMethodAuthorizationEvent(any(MethodInvocation.class), any(Authentication.class), anyBoolean(),
                any())).thenAnswer(call -> event(request));
        repository.writeFinalAction(USER, ZeroTrustAction.ALLOW, Map.of("observationId", "observation-0",
                "processingGeneration", "1", "contextBindingHash", HOME));
    }

    @AfterEach
    void tearDown() {
        release.countDown();
        agent.shutdown();
        threads.shutdownNow();
    }

    private static SecurityEventContext analysed(SecurityEvent event, ZeroTrustAction action) {
        SecurityEventContext context = SecurityEventContext.builder().securityEvent(event)
                .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED).build();
        context.addMetadata("processingResult",
                ProcessingResult.builder().success(true).action(action.name()).llmDecisionPresent(true).build());
        return context;
    }

    private static ZeroTrustSpringEvent event(Map<String, Object> payload) {
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD).userId(USER).sessionId("session-1")
                .clientIp("10.0.0.1").userAgent("browser").resource("/records/1").payload(payload).build();
    }

    private static SecurityEvent signIn(int user) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("zerotrust.category", "AUTHENTICATION");
        return SecurityEvent.builder().eventId(UUID.randomUUID().toString()).userId("user-" + user)
                .sessionId("session-" + user).sourceIp("10.0.0.1").metadata(metadata).build();
    }

    /** The line holds one analysis that does not end, and the next event finds it full. */
    private void theLineIsFull() {
        agent.setAnalysisLineBound(1);
        batches.processBatch(List.of(signIn(1)));
        batches.processBatch(List.of(signIn(2)));
        await().untilAsserted(() -> assertThat(leftOut).hasValue(1));
    }

    private AsyncProtectableGate gate(boolean sensitive) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("contextBindingHash", ELSEWHERE);
        if (sensitive) {
            payload.put("resourceImportance", "SENSITIVE");
        }
        request = payload;
        return service.asyncGate(invocation, alice);
    }

    @Test
    @DisplayName("with the line full a changed context is not made to wait for a verdict")
    void aFullLineDoesNotMakeAChangedContextWait() {
        theLineIsFull();

        assertThat(gate(false)).isEqualTo(AsyncProtectableGate.PROCEED);

        assertThat(asked).hasValue(0);
    }

    @Test
    @DisplayName("with the line full and no room for its analysis a general resource goes on")
    void noRoomEitherLetsAGeneralResourceGoOn() {
        theLineIsFull();
        noRoom.set(true);

        assertThat(gate(false)).isEqualTo(AsyncProtectableGate.PROCEED);

        assertThat(asked).hasValue(0);
    }

    @Test
    @DisplayName("with the line full and no room for its analysis a sensitive resource does not go on: it is told to come back, and nothing waits")
    void noRoomEitherRefusesASensitiveResource() {
        theLineIsFull();
        noRoom.set(true);

        assertThatThrownBy(() -> gate(true)).isInstanceOf(ZeroTrustAccessDeniedException.class)
                .satisfies(refused -> assertThat(((ZeroTrustAccessDeniedException) refused).getBusyRetryAfterSeconds()).isPositive());

        assertThat(asked).hasValue(0);
    }
}
