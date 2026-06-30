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

import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;

@RequiredArgsConstructor
public class LlmAnalysisBackpressureMonitor {

    private final ThreadPoolTaskExecutor executor;
    private final SecurityPlaneProperties securityPlaneProperties;
    private final HcadProperties hcadProperties;

    public Snapshot snapshot() {
        ThreadPoolExecutor nativeExecutor = nativeExecutor();
        if (nativeExecutor == null) {
            SecurityPlaneProperties.LlmExecutorSettings settings = securityPlaneProperties.getLlmExecutor();
            return new Snapshot(0, 0, settings.getMaxPoolSize(), 0, settings.getQueueCapacity(), settings.getQueueCapacity(), false);
        }
        BlockingQueue<Runnable> queue = nativeExecutor.getQueue();
        int queueSize = queue == null ? 0 : queue.size();
        int remainingCapacity = queue == null ? 0 : queue.remainingCapacity();
        int queueCapacity = queueSize + remainingCapacity;
        int configuredThreshold = Math.max(0, hcadProperties.getPreTrigger().getBackpressure().getMaxQueuedLlmTasks());
        boolean queueFull = queueCapacity > 0 && remainingCapacity <= 0;
        boolean thresholdExceeded = hcadPreTriggerBackpressureEnabled()
                && (queueSize >= configuredThreshold || queueFull);
        return new Snapshot(
                nativeExecutor.getActiveCount(),
                nativeExecutor.getPoolSize(),
                nativeExecutor.getMaximumPoolSize(),
                queueSize,
                remainingCapacity,
                queueCapacity,
                thresholdExceeded);
    }

    public boolean hcadPreTriggerBackpressured() {
        return snapshot().thresholdExceeded();
    }

    public String hcadDeferredReason() {
        if (hcadProperties == null
                || hcadProperties.getPreTrigger() == null
                || hcadProperties.getPreTrigger().getBackpressure() == null
                || hcadProperties.getPreTrigger().getBackpressure().getDeferredReason() == null
                || hcadProperties.getPreTrigger().getBackpressure().getDeferredReason().isBlank()) {
            return "TRIGGER_DEFERRED_BACKPRESSURE";
        }
        return hcadProperties.getPreTrigger().getBackpressure().getDeferredReason().trim();
    }

    private boolean hcadPreTriggerBackpressureEnabled() {
        return hcadProperties != null
                && hcadProperties.getPreTrigger() != null
                && hcadProperties.getPreTrigger().getBackpressure() != null
                && hcadProperties.getPreTrigger().getBackpressure().isEnabled();
    }

    private ThreadPoolExecutor nativeExecutor() {
        if (executor == null) {
            return null;
        }
        try {
            return executor.getThreadPoolExecutor();
        } catch (IllegalStateException ex) {
            return null;
        }
    }

    public record Snapshot(
            int activeCount,
            int poolSize,
            int maxPoolSize,
            int queueSize,
            int remainingCapacity,
            int queueCapacity,
            boolean thresholdExceeded) {
    }
}
