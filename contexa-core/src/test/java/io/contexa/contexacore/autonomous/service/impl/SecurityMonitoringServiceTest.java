package io.contexa.contexacore.autonomous.service.impl;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class SecurityMonitoringServiceTest {

    @Mock
    private SecurityEventCollector eventCollector;

    private SecurityMonitoringService service;

    @AfterEach
    void tearDown() {
        if (service != null) {
            service.shutdown();
        }
    }

    @Test
    @DisplayName("processor 등록 전 들어온 이벤트도 queue에 유지됐다가 이후 batch로 처리되어야 한다")
    void shouldQueueEventsUntilProcessorBecomesAvailable() throws Exception {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getMonitor().setQueueSize(32);
        properties.getMonitor().setBatchSize(4);
        properties.getMonitor().setFlushIntervalMs(20);

        service = new SecurityMonitoringService(eventCollector, properties);
        service.initialize();

        ArgumentCaptor<SecurityEventListener> listenerCaptor = ArgumentCaptor.forClass(SecurityEventListener.class);
        verify(eventCollector).registerListener(listenerCaptor.capture());
        SecurityEventListener listener = listenerCaptor.getValue();

        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-queued")
                .userId("user-1")
                .build();

        listener.onSecurityEvent(event);

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<List<SecurityEvent>> processedBatch = new AtomicReference<>();
        service.setBatchProcessor(events -> {
            processedBatch.set(events);
            latch.countDown();
        });

        assertThat(latch.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(processedBatch.get()).hasSize(1);
        assertThat(processedBatch.get().get(0).getEventId()).isEqualTo("evt-queued");
        assertThat(processedBatch.get().get(0).getMetadata())
                .containsEntry("queueMode", "IN_MEMORY_BOUNDED")
                .containsEntry("queueEnqueuePolicy", "BLOCK")
                .containsKeys("queuedAt", "dequeuedAt", "batchId", "batchSize");
    }

    @Test
    @DisplayName("defer 된 이벤트는 신규 이벤트보다 앞에서 다시 처리되어야 한다")
    void shouldDispatchDeferredEventBeforeNewlyQueuedEvent() throws Exception {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getMonitor().setQueueSize(32);
        properties.getMonitor().setBatchSize(1);
        properties.getMonitor().setFlushIntervalMs(20);

        service = new SecurityMonitoringService(eventCollector, properties);
        service.initialize();

        ArgumentCaptor<SecurityEventListener> listenerCaptor = ArgumentCaptor.forClass(SecurityEventListener.class);
        verify(eventCollector).registerListener(listenerCaptor.capture());
        SecurityEventListener listener = listenerCaptor.getValue();

        SecurityEvent deferred = SecurityEvent.builder().eventId("evt-deferred").userId("user-1").build();
        SecurityEvent normal = SecurityEvent.builder().eventId("evt-normal").userId("user-2").build();

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<List<SecurityEvent>> firstBatch = new AtomicReference<>();
        service.deferEvent(deferred, "retry");
        service.setBatchProcessor(events -> {
            firstBatch.compareAndSet(null, events);
            latch.countDown();
        });
        listener.onSecurityEvent(normal);

        assertThat(latch.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(firstBatch.get()).extracting(SecurityEvent::getEventId).containsExactly("evt-deferred");
    }

    @Test
    @DisplayName("shutdown 이후에도 queue에 남아 있던 이벤트는 drain 되어야 한다")
    void shouldDrainQueuedEventsAfterShutdownSignal() throws Exception {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getMonitor().setQueueSize(32);
        properties.getMonitor().setBatchSize(1);
        properties.getMonitor().setFlushIntervalMs(20);

        service = new SecurityMonitoringService(eventCollector, properties);
        service.initialize();

        ArgumentCaptor<SecurityEventListener> listenerCaptor = ArgumentCaptor.forClass(SecurityEventListener.class);
        verify(eventCollector).registerListener(listenerCaptor.capture());
        SecurityEventListener listener = listenerCaptor.getValue();

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<List<SecurityEvent>> drained = new AtomicReference<>();
        service.setBatchProcessor(events -> {
            drained.set(events);
            latch.countDown();
        });

        SecurityEvent event = SecurityEvent.builder().eventId("evt-drain").userId("user-1").build();
        listener.onSecurityEvent(event);
        service.shutdown();

        assertThat(latch.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(drained.get()).extracting(SecurityEvent::getEventId).containsExactly("evt-drain");
    }

    @Test
    @DisplayName("queue가 가득 찬 상태에서는 추가 이벤트 유입이 block 되고 slot이 열리면 다시 진행되어야 한다")
    void shouldBlockAdditionalEnqueueWhenQueueIsFull() throws Exception {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getMonitor().setQueueSize(1);
        properties.getMonitor().setBatchSize(1);
        properties.getMonitor().setFlushIntervalMs(20);

        service = new SecurityMonitoringService(eventCollector, properties);
        service.initialize();

        ArgumentCaptor<SecurityEventListener> listenerCaptor = ArgumentCaptor.forClass(SecurityEventListener.class);
        verify(eventCollector).registerListener(listenerCaptor.capture());
        SecurityEventListener listener = listenerCaptor.getValue();

        SecurityEvent first = SecurityEvent.builder().eventId("evt-first").userId("user-1").build();
        SecurityEvent second = SecurityEvent.builder().eventId("evt-second").userId("user-2").build();
        listener.onSecurityEvent(first);

        var executor = Executors.newSingleThreadExecutor();
        try {
            Future<?> blockedEnqueue = executor.submit(() -> listener.onSecurityEvent(second));
            Thread.sleep(100L);
            assertThat(blockedEnqueue.isDone()).isFalse();

            CountDownLatch latch = new CountDownLatch(2);
            service.setBatchProcessor(events -> latch.countDown());

            assertThat(latch.await(2, TimeUnit.SECONDS)).isTrue();
            blockedEnqueue.get(2, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
    }
}
