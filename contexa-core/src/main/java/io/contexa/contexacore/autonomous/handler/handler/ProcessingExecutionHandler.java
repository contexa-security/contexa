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
package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.handler.strategy.ProcessingStrategy;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@RequiredArgsConstructor
public class ProcessingExecutionHandler implements SecurityEventHandler {

    private final List<ProcessingStrategy> strategies;
    private final Map<ProcessingMode, ProcessingStrategy> strategyCache = new ConcurrentHashMap<>();

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        ProcessingMode mode = (ProcessingMode) context.getMetadata().get("processingMode");

        if (mode == null) {
            mode = ProcessingMode.AI_ANALYSIS;
            context.addMetadata("processingMode", mode);
        }

        ProcessingStrategy strategy;
        try {
            strategy = selectStrategy(mode);
        } catch (Exception e) {
            log.error("[ProcessingExecutionHandler] Error selecting processing strategy for event: {}", event.getEventId(), e);
            context.markAsFailed("Processing strategy selection error: " + e.getMessage());
            return false;
        }

        long startTime = System.currentTimeMillis();
        try {
            ProcessingResult result = strategy.process(context);
            long executionTime = System.currentTimeMillis() - startTime;

            handleProcessingResult(context, result, executionTime);

            return true;

        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            log.error("[ProcessingExecutionHandler] Error executing processing for event: {}", event.getEventId(), e);
            ProcessingResult failedResult = ProcessingResult.builder()
                    .success(false)
                    .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                    .status(ProcessingResult.ProcessingStatus.FAILED)
                    .message("Processing execution error: " + e.getMessage())
                    .errorMessage(e.getMessage())
                    .processingTimeMs(executionTime)
                    .processedAt(LocalDateTime.now())
                    .build();
            context.addMetadata("processingExceptionType", e.getClass().getName());
            handleProcessingResult(context, failedResult, executionTime);
            return true;
        }
    }

    private ProcessingStrategy selectStrategy(ProcessingMode mode) {
        return strategyCache.computeIfAbsent(mode, m ->
            strategies.stream()
                .filter(s -> s.supports(m))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No processing strategy found for mode: " + m))
        );
    }

    private void handleProcessingResult(SecurityEventContext context, ProcessingResult result, long executionTime) {
        context.addMetadata("processingResult", result);

        if (!result.isSuccess()) {
            context.markAsFailed(result.getMessage());
        }

        SecurityEventContext.ProcessingMetrics metrics = context.getProcessingMetrics();
        if (metrics == null) {
            metrics = new SecurityEventContext.ProcessingMetrics();
            context.setProcessingMetrics(metrics);
        }
        metrics.setResponseTimeMs(executionTime);
    }

    @Override
    public String getName() {
        return "ProcessingExecutionHandler";
    }

    @Override
    public int getOrder() {
        return 50;
    }
}
