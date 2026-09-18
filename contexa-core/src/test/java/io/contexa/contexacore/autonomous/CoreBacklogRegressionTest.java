package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.blocking.BlockableServletOutputStream;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter.PersistedFinalDecision;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.zerotrust.InMemoryZeroTrustSecurityService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.time.Duration;
import org.awaitility.Awaitility;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class CoreBacklogRegressionTest {
    private final List<SecurityPlaneAgent> agents = new ArrayList<>();
    private final List<ExecutorService> executors = new ArrayList<>();

    @AfterEach
    void close() {
        executors.forEach(ExecutorService::shutdownNow);
        agents.forEach(SecurityPlaneAgent::shutdown);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ALLOW", "CHALLENGE", "ESCALATE", "BLOCK"})
    void validActionIsReusedWithoutAnotherSynchronousAnalysis(String actionName) {
        String user = UUID.randomUUID().toString();
        InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder(this)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(user).sessionId(UUID.randomUUID().toString())
                .clientIp("127.0.0.1").userAgent("Contexa-Backlog-Regression")
                .resource("/regression/protected").build();
        ZeroTrustEventListener listener = new ZeroTrustEventListener(
                mock(SecurityEventPublisher.class), actions, new SecurityZeroTrustProperties());
        String contextHash = listener.generateAuthorizationContextBindingHash(event);
        ZeroTrustAction action = ZeroTrustAction.valueOf(actionName);
        actions.saveAction(user, action, Map.of("contextBindingHash", contextHash));
        ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
        MethodInvocation invocation = mock(MethodInvocation.class);
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                user, "unused", List.of(new SimpleGrantedAuthority("ROLE_USER")));
        when(publisher.buildMethodAuthorizationEvent(invocation, auth, true, null)).thenReturn(event);
        SecurityPlaneAgent agent = mock(SecurityPlaneAgent.class);
        SynchronousProtectableDecisionService service = new SynchronousProtectableDecisionService(
                publisher, listener, agent, actions);

        assertThat(service.analyze(invocation, auth).action()).isEqualTo(action);
        verifyNoInteractions(agent);
    }

    @Test
    void pendingAnalysisPreservesExistingStaticAuthorities() {
        String user = UUID.randomUUID().toString();
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setEnabled(true);
        InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
        InMemoryZeroTrustSecurityService security = new InMemoryZeroTrustSecurityService(
                mock(ThreatScoreUtil.class), properties, actions, new InMemoryBlockingSignalBroadcaster());
        SimpleGrantedAuthority role = new SimpleGrantedAuthority("ROLE_USER");
        SecurityContextImpl context = new SecurityContextImpl(
                new UsernamePasswordAuthenticationToken(user, "unused", List.of(role)));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/regression/protected");

        security.applyZeroTrustToContext(context, user, null, request);

        assertThat(context.getAuthentication().isAuthenticated()).isTrue();
        assertThat(context.getAuthentication().getAuthorities()).extracting("authority")
                .containsExactlyInAnyOrder("ROLE_USER", ZeroTrustAction.PENDING_ANALYSIS.getGrantedAuthority());
        assertThat(request.getAttribute("contexa.zeroTrustAction")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @ParameterizedTest
    @ValueSource(strings = {"GLOBAL", "EVENT", "PERSISTED_EVENT", "PERSISTED_GLOBAL"})
    void shadowRecoveryNeverEnforces(String boundary) {
        Harness h = new Harness(Runnable::run);
        SecurityEvent event = event();
        if ("GLOBAL".equals(boundary)) {
            h.mode.setMode(SecurityZeroTrustProperties.SecurityMode.SHADOW);
        }
        if ("EVENT".equals(boundary)) {
            event.addMetadata("decisionBoundaryMode", "SHADOW");
        }
        PersistedFinalDecision saved = new PersistedFinalDecision(
                UUID.randomUUID().toString(), null, event.getUserId(), "BLOCK", null,
                UUID.randomUUID().toString(), event.getEventId(),
                "PERSISTED_EVENT".equals(boundary) ? "SHADOW" : null,
                "PERSISTED_GLOBAL".equals(boundary) ? "SHADOW" : null, null);
        when(h.writer.findFinalDecision(anyString())).thenReturn(saved);
        assertThat(h.agent.processSecurityEvent(event).getProcessingStatus())
                .isEqualTo(SecurityEventContext.ProcessingStatus.COMPLETED);
        assertThat(h.actions.getCurrentAction(event.getUserId())).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(h.signals.isBlocked(event.getUserId())).isFalse();
        verifyNoInteractions(h.recorder);
        assertThat(h.analysisCount).hasValue(0);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ACTION", "FLAG", "SIGNAL", "COMPLETE"})
    void blockRecoveryCompletesEveryRequiredEffect(String failure) throws Exception {
        Harness h = new Harness(Runnable::run);
        h.resultAction = "BLOCK";
        SecurityEvent event = event();
        switch (failure) {
            case "ACTION" -> h.actions.failSave.set(1);
            case "FLAG" -> h.actions.failFlag.set(1);
            case "SIGNAL" -> h.signals.failSignal.set(1);
            case "COMPLETE" -> h.store.failComplete.set(1);
            default -> throw new IllegalArgumentException(failure);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        BlockableServletOutputStream stream = new BlockableServletOutputStream(
                response.getOutputStream(), h.signals, event.getUserId(), response);
        stream.write('a');
        assertThatThrownBy(() -> h.agent.processSecurityEvent(event)).isInstanceOf(RuntimeException.class);
        assertThat(h.saved.get()).isNotNull();
        assertThat(h.agent.processSecurityEvent(event).getProcessingStatus())
                .isEqualTo(SecurityEventContext.ProcessingStatus.COMPLETED);
        assertThat(h.analysisCount).hasValue(1);
        assertThat(h.actions.getCurrentAction(event.getUserId())).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(h.signals.isBlocked(event.getUserId())).isTrue();
        assertThatThrownBy(() -> stream.write('b')).isInstanceOf(IOException.class);
        assertThat(response.getContentAsString()).contains("__CONTEXA_RESPONSE_BLOCKED__:BLOCK");
        verify(h.recorder, atLeastOnce()).recordBlock(anyString(), eq(event.getUserId()),
                eq(event.getUserName()), eq("BLOCK"), eq("Controlled regression decision"),
                eq(event.getSourceIp()), eq(event.getUserAgent()));

        h.actions.saveAction(event.getUserId(), ZeroTrustAction.ALLOW, Map.of());
        assertThat(h.actions.getCurrentAction(event.getUserId())).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(h.agent.processSecurityEvent(event).getProcessingStatus())
                .isEqualTo(SecurityEventContext.ProcessingStatus.SKIPPED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ALLOW", "CHALLENGE", "ESCALATE"})
    void legacyEnforceRecoveryKeepsNonBlockAction(String action) {
        Harness h = new Harness(Runnable::run);
        SecurityEvent event = event();
        when(h.writer.findFinalDecision(anyString())).thenReturn(new PersistedFinalDecision(
                UUID.randomUUID().toString(), null, event.getUserId(), action, null,
                UUID.randomUUID().toString(), event.getEventId()));
        h.agent.processSecurityEvent(event);
        assertThat(h.actions.getCurrentAction(event.getUserId())).isEqualTo(ZeroTrustAction.valueOf(action));
        assertThat(h.signals.isBlocked(event.getUserId())).isFalse();
        verifyNoInteractions(h.recorder);
        assertThat(h.analysisCount).hasValue(0);
    }

    @Test
    void logoutPreservesBlockAndMfaButAllowsExplicitResetAndApprovedRelease() {
        Harness h = new Harness(Runnable::run);
        SecurityEvent event = event();
        String user = event.getUserId();
        h.actions.saveAction(user, ZeroTrustAction.BLOCK, Map.of());
        h.actions.setBlockedFlag(user);
        h.actions.setBlockMfaPending(user);
        h.actions.incrementBlockMfaFailCount(user);
        h.signals.registerBlock(user);
        InMemoryZeroTrustSecurityService security = new InMemoryZeroTrustSecurityService(
                null, h.mode, h.actions, h.signals);
        security.cleanupOnLogout(user, "session-b");
        security.cleanupOnLogout(user, null);
        assertThat(h.actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(h.actions.getBlockMfaFailCount(user)).isEqualTo(1);
        assertThat(h.actions.isBlockMfaPending(user)).isTrue();
        assertThat(h.signals.isBlocked(user)).isTrue();

        h.actions.approveOverrideAtomically(user, ZeroTrustAction.ALLOW);
        h.signals.registerUnblock(user);
        security.invalidateDecisionCache(user);
        assertThat(h.actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.ALLOW);
        security.cleanupOnLogout(user, "session-a");
        assertThat(h.actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        h.actions.setBlockedFlag(user);
        h.actions.removeAllUserData(user);
        assertThat(h.actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    void timeoutRetryGetsIndependentOwnerAndLateWorkerCannotOverwriteIt() throws Exception {
        ExecutorService llm = pool(2);
        Harness h = new Harness(llm);
        h.properties.getAgent().setEventTimeoutMs(1000);
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch firstExited = new CountDownLatch(1);
        AtomicReference<SecurityEvent> first = new AtomicReference<>();
        AtomicReference<SecurityEvent> second = new AtomicReference<>();
        h.beforeAnalysis = e -> {
            if (first.compareAndSet(null, e)) {
                firstStarted.countDown();
                try {
                    await(releaseFirst);
                } finally {
                    firstExited.countDown();
                }
            } else {
                second.set(e);
            }
        };
        SecurityEvent event = event();
        CompletableFuture<Throwable> timed = CompletableFuture.supplyAsync(() -> failureWithinBudget(h.agent, event));
        assertThat(firstStarted.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(timed.get(5, TimeUnit.SECONDS)).isNotNull();
        assertThat(event.getMetadata()).containsEntry("processingTimedOut", true);
        String oldOwner = String.valueOf(first.get().getMetadata().get(SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN));
        SecurityEventContext retried = withinBudget(h.agent, event);
        assertThat(retried.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.COMPLETED);
        assertThat(second.get()).isNotSameAs(first.get());
        assertThat(second.get().getMetadata().get(SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN)).isNotEqualTo(oldOwner);
        assertThat(h.actions.getCurrentAction(event.getUserId())).isEqualTo(ZeroTrustAction.ALLOW);
        releaseFirst.countDown();
        assertThat(firstExited.await(5, TimeUnit.SECONDS)).isTrue();
        llm.shutdown();
        assertThat(llm.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        assertThat(event.getMetadata()).containsEntry("processingTimedOut", false);
        assertThat(h.actions.getCurrentAction(event.getUserId())).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(h.agent.processSecurityEvent(event).getProcessingStatus())
                .isEqualTo(SecurityEventContext.ProcessingStatus.SKIPPED);
        verify(h.writer, times(1)).recordDecision(any(), argThat(r -> r != null && r.isSuccess()), eq(ZeroTrustAction.ALLOW));
    }

    @Test
    void executorQueueTimeoutCanRetryAfterQueueRecovers() throws Exception {
        LinkedBlockingQueue<Runnable> submitted = new LinkedBlockingQueue<>();
        Harness h = new Harness(submitted::add);
        h.properties.getAgent().setEventTimeoutMs(5000);
        h.properties.getLlmExecutor().setQueueTimeoutMs(1);
        SecurityEvent event = event();
        CompletableFuture<Throwable> timed = CompletableFuture.supplyAsync(() -> failureWithinBudget(h.agent, event));
        Runnable first = submitted.poll(5, TimeUnit.SECONDS);
        assertThat(first).isNotNull();
        new CountDownLatch(1).await(15, TimeUnit.MILLISECONDS);
        first.run();
        assertThat(timed.get(5, TimeUnit.SECONDS)).isNotNull();
        assertThat(event.getMetadata()).containsEntry("decisionFailureCategory", "QUEUE_TIMEOUT");
        h.properties.getLlmExecutor().setQueueTimeoutMs(0);
        CompletableFuture<SecurityEventContext> retry = CompletableFuture.supplyAsync(() -> withinBudget(h.agent, event));
        Runnable next = submitted.poll(5, TimeUnit.SECONDS);
        assertThat(next).isNotNull();
        next.run();
        assertThat(retry.get(5, TimeUnit.SECONDS).getProcessingStatus())
                .isEqualTo(SecurityEventContext.ProcessingStatus.COMPLETED);
        assertThat(event.getMetadata()).containsEntry("processingTimedOut", false);
        assertThat(event.getMetadata()).doesNotContainKey("decisionFailureCategory");
        assertThat(h.analysisCount).hasValue(1);
    }

    @Test
    void submissionAndRetirementShareTheSameKeyBoundary() throws Exception {
        Harness h = new Harness(Runnable::run);
        h.agent.initialize();
        Object serial = ReflectionTestUtils.getField(h.agent, "actorSerialExecutor");
        GatedQueues queues = new GatedQueues();
        ReflectionTestUtils.setField(serial, "queues", queues);
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maximum = new AtomicInteger();
        List<Integer> order = new CopyOnWriteArrayList<>();
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch endFirst = new CountDownLatch(1);
        CountDownLatch laterDone = new CountDownLatch(2);
        CountDownLatch secondStarted = new CountDownLatch(1);
        CountDownLatch endSecond = new CountDownLatch(1);
        ReflectionTestUtils.invokeMethod(serial, "execute", "same-key", (Runnable) () -> {
            maximum.accumulateAndGet(active.incrementAndGet(), Math::max);
            order.add(1);
            firstStarted.countDown();
            await(endFirst);
            active.decrementAndGet();
        });
        assertThat(firstStarted.await(5, TimeUnit.SECONDS)).isTrue();
        Thread producer = new Thread(() -> {
            queues.producer = Thread.currentThread();
            ReflectionTestUtils.invokeMethod(serial, "execute", "same-key", (Runnable) () -> {
                maximum.accumulateAndGet(active.incrementAndGet(), Math::max);
                order.add(2);
                secondStarted.countDown();
                await(endSecond);
                active.decrementAndGet();
                laterDone.countDown();
            });
        });
        producer.start();
        assertThat(queues.lookup.await(5, TimeUnit.SECONDS)).isTrue();
        endFirst.countDown();
        assertThat(queues.retiring.await(5, TimeUnit.SECONDS)).isTrue();
        queues.resume.countDown();
        producer.join(5000);
        assertThat(producer.isAlive()).isFalse();
        assertThat(secondStarted.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(queues).containsKey("same-key");
        ReflectionTestUtils.invokeMethod(serial, "execute", "same-key", (Runnable) () -> {
            maximum.accumulateAndGet(active.incrementAndGet(), Math::max);
            order.add(3);
            active.decrementAndGet();
            laterDone.countDown();
        });
        endSecond.countDown();
        assertThat(laterDone.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(maximum).hasValue(1);
        assertThat(order).containsExactly(1, 2, 3);
    }


    @Test
    void independentKeysRemainParallelAndIdleKeysCanBeReused() throws Exception {
        Harness h = new Harness(Runnable::run);
        h.agent.initialize();
        Object serial = ReflectionTestUtils.getField(h.agent, "actorSerialExecutor");
        CountDownLatch running = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch finished = new CountDownLatch(2);
        for (String key : List.of("actor-a", "actor-b")) {
            ReflectionTestUtils.invokeMethod(serial, "execute", key, (Runnable) () -> {
                running.countDown();
                await(release);
                finished.countDown();
            });
        }
        assertThat(running.await(5, TimeUnit.SECONDS)).isTrue();
        release.countDown();
        assertThat(finished.await(5, TimeUnit.SECONDS)).isTrue();
        Map<?, ?> queues = (Map<?, ?>) ReflectionTestUtils.getField(serial, "queues");
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(queues::isEmpty);
        CountDownLatch reused = new CountDownLatch(1);
        ReflectionTestUtils.invokeMethod(serial, "execute", "actor-a", (Runnable) reused::countDown);
        assertThat(reused.await(5, TimeUnit.SECONDS)).isTrue();
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(queues::isEmpty);
    }

    @Test
    void oldWorkerCannotReleaseAnActiveRetryLease() throws Exception {
        ExecutorService llm = pool(2);
        Harness h = new Harness(llm);
        h.properties.getAgent().setEventTimeoutMs(1000);
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch secondStarted = new CountDownLatch(1);
        CountDownLatch releaseSecond = new CountDownLatch(1);
        AtomicReference<SecurityEvent> first = new AtomicReference<>();
        AtomicReference<SecurityEvent> second = new AtomicReference<>();
        h.beforeAnalysis = event -> {
            if (first.compareAndSet(null, event)) {
                firstStarted.countDown();
                await(releaseFirst);
            } else {
                second.set(event);
                secondStarted.countDown();
                await(releaseSecond);
            }
        };
        SecurityEvent event = event();
        CompletableFuture<Throwable> expired = CompletableFuture.supplyAsync(() -> failureWithinBudget(h.agent, event));
        assertThat(firstStarted.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(expired.get(5, TimeUnit.SECONDS)).isNotNull();
        h.properties.getAgent().setEventTimeoutMs(10000);
        CompletableFuture<SecurityEventContext> retry = CompletableFuture.supplyAsync(() -> withinBudget(h.agent, event));
        assertThat(secondStarted.await(5, TimeUnit.SECONDS)).isTrue();
        releaseFirst.countDown();
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(() ->
                first.get().getMetadata().containsKey("analysisExecutionFinishedAt"));
        String identity = String.valueOf(second.get().getMetadata().get(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY));
        String owner = String.valueOf(second.get().getMetadata().get(SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN));
        assertThat(h.store.isEventProcessingOwner(identity, owner)).isTrue();
        assertThat(first.get().getMetadata().get(SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN)).isNotEqualTo(owner);
        assertThat(h.actions.getCurrentAction(event.getUserId())).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        releaseSecond.countDown();
        assertThat(retry.get(5, TimeUnit.SECONDS).getProcessingStatus())
                .isEqualTo(SecurityEventContext.ProcessingStatus.COMPLETED);
        assertThat(h.actions.getCurrentAction(event.getUserId())).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @ParameterizedTest
    @ValueSource(strings = {"GLOBAL", "EVENT"})
    void shadowObservationSurvivesCompletionFailureAndModeChange(String boundary) {
        Harness h = new Harness(Runnable::run);
        h.resultAction = "BLOCK";
        SecurityEvent event = event();
        if ("GLOBAL".equals(boundary)) {
            h.mode.setMode(SecurityZeroTrustProperties.SecurityMode.SHADOW);
        } else {
            event.addMetadata("decisionBoundaryMode", "SHADOW");
        }
        h.store.failComplete.set(1);
        assertThatThrownBy(() -> h.agent.processSecurityEvent(event)).isInstanceOf(RuntimeException.class);
        assertThat(h.saved.get().runtimeEnforcementMode()).isEqualTo("SHADOW");
        h.mode.setMode(SecurityZeroTrustProperties.SecurityMode.ENFORCE);
        event.getMetadata().remove("decisionBoundaryMode");
        h.agent.processSecurityEvent(event);
        assertThat(h.analysisCount).hasValue(1);
        assertThat(h.actions.getCurrentAction(event.getUserId())).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(h.signals.isBlocked(event.getUserId())).isFalse();
        verifyNoInteractions(h.recorder);
    }

    @Test
    void retryExhaustionKeepsTheExistingRequeueLimit() {
        Harness h = new Harness(Runnable::run);
        h.properties.getAgent().setMaxDeferredRetries(2);
        SecurityMonitoringService monitor = new SecurityMonitoringService(
                mock(SecurityEventCollector.class), h.properties);
        ReflectionTestUtils.setField(h.agent, "securityMonitor", monitor);
        SecurityEvent event = event();
        Boolean first = ReflectionTestUtils.invokeMethod(h.agent, "deferForRetry", event, "TIMEOUT", null);
        Boolean second = ReflectionTestUtils.invokeMethod(h.agent, "deferForRetry", event, "TIMEOUT", null);
        Boolean exhausted = ReflectionTestUtils.invokeMethod(h.agent, "deferForRetry", event, "TIMEOUT", null);
        assertThat(first).isTrue();
        assertThat(second).isTrue();
        assertThat(exhausted).isFalse();
        assertThat(event.getMetadata()).containsEntry("deferredCount", 2).containsEntry("deferExhausted", true);
        monitor.shutdown();
    }

    private static class GatedQueues extends ConcurrentHashMap<String, Object> {
        volatile Thread producer;
        final CountDownLatch lookup = new CountDownLatch(1);
        final CountDownLatch retiring = new CountDownLatch(1);
        final CountDownLatch resume = new CountDownLatch(1);

        @Override
        public Object compute(String key, BiFunction<? super String, ? super Object, ?> function) {
            return super.compute(key, (k, q) -> {
                gate();
                return function.apply(k, q);
            });
        }

        @Override
        public Object computeIfAbsent(String key, Function<? super String, ?> function) {
            Object queue = super.computeIfAbsent(key, function);
            gate();
            return queue;
        }

        @Override
        public Object computeIfPresent(String key, BiFunction<? super String, ? super Object, ?> function) {
            if (producer != null) {
                retiring.countDown();
            }
            return super.computeIfPresent(key, function);
        }

        @Override
        public boolean remove(Object key, Object value) {
            boolean removed = super.remove(key, value);
            retiring.countDown();
            return removed;
        }

        private void gate() {
            if (Thread.currentThread() == producer) {
                lookup.countDown();
                await(resume);
            }
        }
    }

    private class Harness {
        final FaultActions actions = new FaultActions();
        final FaultSignals signals = new FaultSignals();
        final FaultStore store = new FaultStore();
        final SecurityZeroTrustProperties mode = new SecurityZeroTrustProperties();
        final SecurityPlaneProperties properties = new SecurityPlaneProperties();
        final AiSecurityDecisionObservationWriter writer = mock(AiSecurityDecisionObservationWriter.class);
        final IBlockedUserRecorder recorder = mock(IBlockedUserRecorder.class);
        final AtomicReference<PersistedFinalDecision> saved = new AtomicReference<>();
        final AtomicInteger analysisCount = new AtomicInteger();
        Consumer<SecurityEvent> beforeAnalysis = e -> {};
        String resultAction = "ALLOW";
        final SecurityPlaneAgent agent;

        Harness(Executor executor) {
            mode.setMode(SecurityZeroTrustProperties.SecurityMode.ENFORCE);
            when(writer.findFinalDecision(anyString())).thenAnswer(i -> saved.get());
            when(writer.recordDecision(any(), any(), any())).thenAnswer(i -> {
                SecurityEvent event = i.getArgument(0);
                ProcessingResult result = i.getArgument(1);
                String id = UUID.randomUUID().toString();
                if (result.isSuccess()) {
                    saved.set(new PersistedFinalDecision(id, null, event.getUserId(), result.getAction(), null,
                            String.valueOf(event.getMetadata().get(SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN)),
                            event.getEventId(), (String) event.getMetadata().get("decisionBoundaryMode"),
                            (String) event.getMetadata().get("runtimeEnforcementMode"), result.getReasoning()));
                }
                return id;
            });
            SecurityDecisionEnforcementHandler enforcement = new SecurityDecisionEnforcementHandler(
                    actions, null, recorder, signals, mode, Runnable::run, () -> writer, store);
            SecurityEventHandler analysis = mock(SecurityEventHandler.class);
            when(analysis.getOrder()).thenReturn(0);
            when(analysis.getName()).thenReturn("ControlledAnalysis");
            when(analysis.canHandle(any())).thenReturn(true);
            when(analysis.handle(any())).thenAnswer(i -> {
                SecurityEventContext context = i.getArgument(0);
                analysisCount.incrementAndGet();
                beforeAnalysis.accept(context.getSecurityEvent());
                context.addMetadata("processingResult", ProcessingResult.builder().success(true)
                        .action(resultAction).reasoning("Controlled regression decision").build());
                return true;
            });
            properties.getAgent().setAutoStart(false);
            properties.getAgent().setAnalysisStripes(2);
            properties.getAgent().setEventTimeoutMs(5000);
            agent = new SecurityPlaneAgent(mock(SecurityMonitoringService.class), store, null,
                    new SecurityEventProcessor(List.of(analysis, enforcement), "backlog-test"), properties, executor);
            agent.setZeroTrustActionRepository(actions);
            agent.setAiSecurityDecisionObservationWriterSupplier(() -> writer);
            agent.setDecisionEnforcementHandlerSupplier(() -> enforcement);
            agents.add(agent);
        }
    }

    private static class FaultActions extends InMemoryZeroTrustActionRepository {
        final AtomicInteger failSave = new AtomicInteger();
        final AtomicInteger failFlag = new AtomicInteger();

        @Override
        public boolean saveFinalAction(String user, ZeroTrustAction action, Map<String, Object> fields) {
            if (failSave.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
                return false;
            }
            return super.saveFinalAction(user, action, fields);
        }

        @Override
        public void setBlockedFlag(String user) {
            if (failFlag.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
                throw new IllegalStateException("Injected flag storage failure");
            }
            super.setBlockedFlag(user);
        }
    }

    private static class FaultSignals extends InMemoryBlockingSignalBroadcaster {
        final AtomicInteger failSignal = new AtomicInteger();

        @Override
        public void registerBlockAndAwait(String user) {
            if (failSignal.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
                throw new IllegalStateException("Injected signal failure");
            }
            super.registerBlockAndAwait(user);
        }
    }

    private static class FaultStore extends InMemorySecurityContextDataStore {
        final AtomicInteger failComplete = new AtomicInteger();

        @Override
        public boolean markEventProcessed(String identity, String owner) {
            if (failComplete.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
                throw new IllegalStateException("Injected completion failure");
            }
            return super.markEventProcessed(identity, owner);
        }
    }

    private ExecutorService pool(int size) {
        ExecutorService executor = Executors.newFixedThreadPool(size);
        executors.add(executor);
        return executor;
    }

    private SecurityEvent event() {
        SecurityEvent event = SecurityEvent.builder().userId(UUID.randomUUID().toString())
                .userName("Backlog regression").sessionId(UUID.randomUUID().toString())
                .sourceIp("127.0.0.1").userAgent("Contexa-Backlog-Test").build();
        event.addMetadata("requestId", event.getEventId());
        return event;
    }

    private static SecurityEventContext withinBudget(SecurityPlaneAgent agent, SecurityEvent event) {
        return ReflectionTestUtils.invokeMethod(agent, "processSecurityEventWithinBudget", event);
    }

    private static Throwable failureWithinBudget(SecurityPlaneAgent agent, SecurityEvent event) {
        try {
            withinBudget(agent, event);
            return null;
        } catch (Throwable exception) {
            return exception;
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Regression latch timed out");
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(exception);
        }
    }
}

