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

import io.contexa.contexacore.properties.SecurityPlaneProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;

@RequiredArgsConstructor
public class LlmAnalysisBackpressureMonitor {

    public static final String DEFERRED_REASON = "LLM_DEFERRED_BACKPRESSURE";

    private final ThreadPoolTaskExecutor executor;
    private final SecurityPlaneProperties securityPlaneProperties;

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
        SecurityPlaneProperties.LlmExecutorSettings settings = securityPlaneProperties.getLlmExecutor();
        int configuredThreshold = Math.max(0, settings.getBackpressureQueueThreshold());
        boolean queueFull = queueCapacity > 0 && remainingCapacity <= 0;
        boolean thresholdExceeded = settings.isBackpressureEnabled()
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

    public boolean isBackpressured() {
        return snapshot().thresholdExceeded();
    }

    public String deferredReason() {
        return DEFERRED_REASON;
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
