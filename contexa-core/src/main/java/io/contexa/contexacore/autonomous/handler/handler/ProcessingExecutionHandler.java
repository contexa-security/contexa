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
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.handler.strategy.ProcessingStrategy;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.util.ErrorLogThrottle;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@RequiredArgsConstructor
public class ProcessingExecutionHandler implements SecurityEventHandler {

    private static final Duration STRATEGY_SELECTION_LOG_INTERVAL = Duration.ofMinutes(5);

    private final List<ProcessingStrategy> strategies;
    private final Map<ProcessingMode, ProcessingStrategy> strategyCache = new ConcurrentHashMap<>();
    private final ErrorLogThrottle strategySelectionLogThrottle = new ErrorLogThrottle(STRATEGY_SELECTION_LOG_INTERVAL);

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        ProcessingMode mode = (ProcessingMode) context.getMetadata().get("processingMode");

        if (mode == null) {
            mode = ProcessingMode.AI_ANALYSIS;
            context.addMetadata("processingMode", mode);
        }

        ProcessingResult auditPendingResult = takeAuditPendingResult(event);
        if (auditPendingResult != null) {
            // The decision was already produced for this event; only its observation is retried.
            event.addMetadata("auditPendingDecisionReused", true);
            context.addMetadata("auditPendingDecisionReused", true);
            handleProcessingResult(context, auditPendingResult, 0L);
            return true;
        }

        ProcessingStrategy strategy;
        try {
            strategy = selectStrategy(mode);
        } catch (Exception e) {
            reportStrategySelectionFailure(event, mode, e);
            context.markAsFailed("Processing strategy selection error: " + e.getMessage());
            return false;
        }

        long startTime = System.currentTimeMillis();
        try {
            ProcessingResult result = strategy.process(context);
            long executionTime = System.currentTimeMillis() - startTime;
            context.addMetadata("processingStrategyMs", executionTime);
            context.addMetadata("processingStrategyMode", mode.name());
            event.addMetadata("processingStrategyMs", executionTime);
            event.addMetadata("processingStrategyMode", mode.name());
            log.info("[ProcessingExecutionHandler.timing] eventId={} mode={} strategy={} durationMs={}",
                    event.getEventId(), mode, strategy.getClass().getName(), executionTime);

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
            context.addMetadata("processingStrategyMs", executionTime);
            context.addMetadata("processingStrategyMode", mode.name());
            event.addMetadata("processingExceptionType", e.getClass().getName());
            event.addMetadata("processingStrategyMs", executionTime);
            event.addMetadata("processingStrategyMode", mode.name());
            log.info("[ProcessingExecutionHandler.timing] eventId={} mode={} strategy={} durationMs={} failed=true",
                    event.getEventId(), mode, strategy.getClass().getName(), executionTime);
            handleProcessingResult(context, failedResult, executionTime);
            return true;
        }
    }

    private ProcessingResult takeAuditPendingResult(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return null;
        }
        Object retained = event.getMetadata().get(SecurityDecisionEnforcementHandler.AUDIT_PENDING_PROCESSING_RESULT);
        if (!(retained instanceof ProcessingResult result) || !result.isSuccess()) {
            return null;
        }
        event.getMetadata().remove(SecurityDecisionEnforcementHandler.AUDIT_PENDING_PROCESSING_RESULT);
        return result;
    }

    private void reportStrategySelectionFailure(SecurityEvent event, ProcessingMode mode, Exception exception) {
        if (event != null) {
            event.addMetadata(SecurityPlaneAgent.PROCESSING_STRATEGY_UNAVAILABLE, true);
            event.addMetadata(SecurityPlaneAgent.PROCESSING_FAILURE_REPORTED, true);
        }
        long suppressed = strategySelectionLogThrottle.tryAcquire();
        if (suppressed == ErrorLogThrottle.SUPPRESSED) {
            return;
        }
        List<String> registered = strategies == null ? List.of() : strategies.stream()
                .map(strategy -> strategy.getClass().getSimpleName())
                .toList();
        log.error("[ProcessingExecutionHandler] No processing strategy can handle mode {} ({}). Registered strategies: {}. "
                        + "No autonomous decision can be produced, so actors stay PENDING_ANALYSIS. The cold path "
                        + "strategy needs Layer1ContextualStrategy and Layer2ExpertStrategy, which are created only when "
                        + "a Spring AI ChatModel and a VectorStore are configured. eventId={}, similarFailuresSinceLastReport={}",
                mode, exception.getMessage(), registered, event != null ? event.getEventId() : null, suppressed);
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
