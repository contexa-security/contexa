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
package io.contexa.contexacore.autonomous.service.impl;

import io.contexa.contexacore.SecurityEvent;
import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class SecurityMonitoringService {

    private static final Logger log = LoggerFactory.getLogger(SecurityMonitoringService.class);
    private static final int DEFAULT_BATCH_SIZE = 50;
    private static final String QUEUE_MODE = "IN_MEMORY_BOUNDED";
    private static final String QUEUE_ENQUEUE_POLICY = "BLOCK";

    @FunctionalInterface
    public interface SecurityEventBatchProcessor {
        void processBatch(List<SecurityEvent> events);
    }

    private final SecurityEventCollector eventCollector;
    private final AtomicLong eventCounter;
    private final AtomicLong enqueuedCounter;
    private final AtomicLong batchDispatchCounter;
    private final AtomicLong deferredCounter;
    private final AtomicLong batchSequence;
    private final BlockingDeque<SecurityEvent> eventQueue;
    private final AtomicBoolean running;
    private final List<Thread> dispatcherThreads;
    private final long flushIntervalMs;
    private final int batchSize;
    private final int maxBatchRequeueAttempts;

    private volatile SecurityEventBatchProcessor batchProcessor;

    public SecurityMonitoringService(SecurityEventCollector eventCollector,
                                     SecurityPlaneProperties securityPlaneProperties) {
        this.eventCollector = eventCollector;
        this.eventCounter = new AtomicLong(0);
        this.enqueuedCounter = new AtomicLong(0);
        this.batchDispatchCounter = new AtomicLong(0);
        this.deferredCounter = new AtomicLong(0);
        this.batchSequence = new AtomicLong(0);
        this.running = new AtomicBoolean(false);

        SecurityPlaneProperties.MonitorSettings monitorSettings = securityPlaneProperties.getMonitor();
        int queueSize = Math.max(1, monitorSettings.getQueueSize());
        int configuredBatchSize = monitorSettings.getBatchSize() > 0
                ? monitorSettings.getBatchSize()
                : DEFAULT_BATCH_SIZE;
        this.batchSize = Math.max(1, Math.min(queueSize, configuredBatchSize));
        this.flushIntervalMs = Math.max(10L, monitorSettings.getFlushIntervalMs());
        SecurityPlaneProperties.AgentSettings agentSettings = securityPlaneProperties.getAgent();
        this.maxBatchRequeueAttempts = agentSettings != null
                ? Math.max(0, agentSettings.getMaxDeferredRetries())
                : 0;
        this.eventQueue = new LinkedBlockingDeque<>(queueSize);
        this.dispatcherThreads = new ArrayList<>(1);
        Thread dispatcherThread = new Thread(this::dispatchLoop, "SecurityMonitoring-BatchDispatcher-0");
        dispatcherThread.setDaemon(true);
        this.dispatcherThreads.add(dispatcherThread);
    }

    public void setBatchProcessor(SecurityEventBatchProcessor processor) {
        this.batchProcessor = processor;
    }

    @PostConstruct
    public void initialize() {
        running.set(true);
        eventCollector.registerListener(new DefaultBatchEventListener());
        dispatcherThreads.forEach(Thread::start);
    }

    @PreDestroy
    public void shutdown() {
        running.set(false);
        dispatcherThreads.forEach(Thread::interrupt);
        for (Thread dispatcherThread : dispatcherThreads) {
            try {
                dispatcherThread.join(Math.max(1000L, flushIntervalMs * 2));
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private SecurityEvent preprocessEvent(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        eventCounter.incrementAndGet();
        return event;
    }

    private void dispatchLoop() {
        while (running.get() || !eventQueue.isEmpty()) {
            List<SecurityEvent> batch = null;
            try {
                SecurityEventBatchProcessor processor = batchProcessor;
                if (processor == null) {
                    TimeUnit.MILLISECONDS.sleep(flushIntervalMs);
                    continue;
                }

                SecurityEvent first = eventQueue.pollFirst(flushIntervalMs, TimeUnit.MILLISECONDS);
                if (first == null) {
                    continue;
                }

                batch = new ArrayList<>(batchSize);
                batch.add(first);
                eventQueue.drainTo(batch, batchSize - 1);
                annotateBatch(batch);

                processor.processBatch(List.copyOf(batch));
                batchDispatchCounter.incrementAndGet();
            } catch (InterruptedException interruptedException) {
                if (running.get()) {
                    Thread.currentThread().interrupt();
                    log.warn("[SecurityMonitoringService] Dispatcher interrupted while still running", interruptedException);
                    break;
                }
                Thread.interrupted();
            } catch (Exception e) {
                log.error("[SecurityMonitoringService] Failed to dispatch queued batch", e);
                requeueAtFront(batch, e);
            }
        }
    }

    private void enqueueForProcessing(List<SecurityEvent> events) {
        for (SecurityEvent event : events) {
            try {
                annotateQueueEnqueue(event, false, null);
                eventQueue.putLast(event);
                enqueuedCounter.incrementAndGet();
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while enqueueing security event batch", interruptedException);
            }
        }
    }

    public void deferEvent(SecurityEvent event, String reason) {
        if (event == null) {
            return;
        }
        try {
            annotateQueueEnqueue(event, true, reason);
            eventQueue.putFirst(event);
            enqueuedCounter.incrementAndGet();
            deferredCounter.incrementAndGet();
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while deferring security event", interruptedException);
        }
    }

    private void requeueAtFront(List<SecurityEvent> batch, Exception failure) {
        if (batch == null || batch.isEmpty()) {
            return;
        }

        for (int i = batch.size() - 1; i >= 0; i--) {
            SecurityEvent event = batch.get(i);
            if (!markBatchDispatchFailureForRetry(event, failure)) {
                continue;
            }
            try {
                eventQueue.putFirst(event);
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while requeueing failed security event batch", interruptedException);
            }
        }
    }

    private boolean markBatchDispatchFailureForRetry(SecurityEvent event, Exception failure) {
        if (event == null) {
            return false;
        }

        int failureCount = getIntegerMetadata(event, "batchDispatchFailureCount") + 1;
        long now = System.currentTimeMillis();
        event.addMetadata("batchDispatchFailureCount", failureCount);
        event.addMetadata("lastBatchDispatchFailureAt", now);
        if (failure != null) {
            event.addMetadata("lastBatchDispatchFailureClass", failure.getClass().getName());
            event.addMetadata("lastBatchDispatchFailureMessage", failure.getMessage());
        }

        if (failureCount > maxBatchRequeueAttempts) {
            event.addMetadata("batchRequeueExhausted", true);
            event.addMetadata("batchRequeueExhaustedAt", now);
            event.addMetadata("batchRequeueExhaustedReason", "max_batch_requeue_attempts_exceeded");
            log.error("[SecurityMonitoringService] Dropping queued security event after batch requeue budget exhausted: eventId={}, attempts={}, maxAttempts={}",
                    event.getEventId(), failureCount, maxBatchRequeueAttempts);
            return false;
        }

        event.addMetadata("batchRequeueRequestedAt", now);
        return true;
    }

    private void annotateQueueEnqueue(SecurityEvent event, boolean deferred, String reason) {
        long now = System.currentTimeMillis();
        event.addMetadata("queuedAt", now);
        event.addMetadata("queueDepthAtEnqueue", eventQueue.size());
        event.addMetadata("queueMode", QUEUE_MODE);
        event.addMetadata("queueEnqueuePolicy", QUEUE_ENQUEUE_POLICY);
        event.addMetadata("queueCapacity", eventQueue.remainingCapacity() + eventQueue.size());
        event.addMetadata("configuredBatchSize", batchSize);
        event.addMetadata("configuredFlushIntervalMs", flushIntervalMs);
        if (deferred) {
            int deferredCount = getIntegerMetadata(event, "deferredCount") + 1;
            event.addMetadata("deferredCount", deferredCount);
            event.addMetadata("lastDeferredAt", now);
            if (reason != null && !reason.isBlank()) {
                event.addMetadata("lastDeferredReason", reason);
            }
        }
    }

    private void annotateBatch(List<SecurityEvent> batch) {
        if (batch == null || batch.isEmpty()) {
            return;
        }
        long batchId = batchSequence.incrementAndGet();
        long now = System.currentTimeMillis();
        int size = batch.size();
        for (SecurityEvent event : batch) {
            event.addMetadata("dequeuedAt", now);
            event.addMetadata("batchId", batchId);
            event.addMetadata("batchSize", size);
        }
    }

    private int getIntegerMetadata(SecurityEvent event, String key) {
        Object value = event.getMetadata() != null ? event.getMetadata().get(key) : null;
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String stringValue) {
            try {
                return Integer.parseInt(stringValue);
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private class DefaultBatchEventListener implements SecurityEventListener {
        @Override
        public void onSecurityEvent(SecurityEvent event) {
            if (event == null) {
                return;
            }

            SecurityEvent processed = preprocessEventSafe(event);
            if (processed == null) {
                return;
            }

            enqueueForProcessing(List.of(processed));
        }

        @Override
        public String getListenerName() {
            return "QueuedBatchListener";
        }

        private SecurityEvent preprocessEventSafe(SecurityEvent event) {
            try {
                return preprocessEvent(event);
            } catch (Exception e) {
                SecurityMonitoringService.log.error("[QueuedBatchListener] Error preprocessing event: {}", event.getEventId(), e);
                return null;
            }
        }
    }
}
