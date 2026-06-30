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
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
@RequiredArgsConstructor
public class SecurityEventProcessor {

    static final String PROCESSING_DEADLINE_AT = "processingDeadlineAt";
    static final String PROCESSING_TIMED_OUT = "processingTimedOut";
    static final String PROCESSING_DEADLINE_EXCEEDED = "processingDeadlineExceeded";
    static final String PROCESSING_DEADLINE_EXCEEDED_AT = "processingDeadlineExceededAt";
    static final String PROCESSING_DEADLINE_EXCEEDED_BEFORE_HANDLER = "processingDeadlineExceededBeforeHandler";

    private final List<SecurityEventHandler> handlers;
    private final AtomicBoolean handlerTopologyLogged = new AtomicBoolean(false);

    public SecurityEventContext process(SecurityEvent event) {
        long startTime = System.currentTimeMillis();

        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .processingStatus(SecurityEventContext.ProcessingStatus.PENDING)
                .createdAt(LocalDateTime.now())
                .build();

        context.addMetadata("agentId", "security-plane-agent");

        try {

            List<SecurityEventHandler> sortedHandlers = getSortedHandlers();
            logHandlerTopologyOnce(sortedHandlers);

            for (SecurityEventHandler handler : sortedHandlers) {
                if (markFailedIfProcessingDeadlineExceeded(context, handler.getName())) {
                    break;
                }
                if (!executeHandler(handler, context)) {
                    break;
                }
            }

            if (context.getProcessingStatus() != SecurityEventContext.ProcessingStatus.FAILED
                    && !markFailedIfProcessingDeadlineExceeded(context, "pipeline-completion")) {
                context.markAsCompleted();
            }

        } catch (Exception e) {
            log.error("[Orchestrator] Unexpected error in processing pipeline - eventId: {}",
                    event.getEventId(), e);
            context.markAsFailed("Orchestrator error: " + e.getMessage());
        } finally {
            recordProcessingMetrics(context, startTime);
        }

        return context;
    }

    private boolean markFailedIfProcessingDeadlineExceeded(SecurityEventContext context, String nextHandlerName) {
        if (context == null || !hasProcessingDeadlineExceeded(context.getSecurityEvent())) {
            return false;
        }
        context.addMetadata(PROCESSING_DEADLINE_EXCEEDED, true);
        context.addMetadata(PROCESSING_DEADLINE_EXCEEDED_AT, System.currentTimeMillis());
        if (nextHandlerName != null && !nextHandlerName.isBlank()) {
            context.addMetadata(PROCESSING_DEADLINE_EXCEEDED_BEFORE_HANDLER, nextHandlerName);
        }
        context.markAsFailed("Security event processing deadline exceeded");
        return true;
    }

    static boolean hasProcessingDeadlineExceeded(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return false;
        }
        Object timedOut = event.getMetadata().get(PROCESSING_TIMED_OUT);
        if (Boolean.TRUE.equals(timedOut)) {
            return true;
        }
        Object deadlineValue = event.getMetadata().get(PROCESSING_DEADLINE_AT);
        Long deadlineAt = toLong(deadlineValue);
        return deadlineAt != null && deadlineAt > 0 && System.currentTimeMillis() > deadlineAt;
    }

    private static Long toLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String stringValue) {
            try {
                return Long.parseLong(stringValue);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private boolean executeHandler(SecurityEventHandler handler, SecurityEventContext context) {

        if (!handler.canHandle(context)) {
            return true;
        }

        try {
            long handlerStartTime = System.currentTimeMillis();

            boolean continueChain = handler.handle(context);

            long handlerTime = System.currentTimeMillis() - handlerStartTime;
            String timingKey = handler.getName() + "_executionTime";
            context.addMetadata(timingKey, handlerTime);
            if (context.getSecurityEvent() != null) {
                context.getSecurityEvent().addMetadata(timingKey, handlerTime);
            }
            log.info("[SecurityEventProcessor.timing] eventId={} handler={} durationMs={} continue={}",
                    context.getSecurityEvent() != null ? context.getSecurityEvent().getEventId() : "unknown",
                    handler.getName(),
                    handlerTime,
                    continueChain);

            return continueChain;

        } catch (Exception e) {
            log.error("[Orchestrator] Error in handler {} for event: {}",
                    handler.getName(), context.getSecurityEvent().getEventId(), e);

            handler.handleError(context, e);

            return true;
        }
    }

    private List<SecurityEventHandler> getSortedHandlers() {
        List<SecurityEventHandler> sorted = new ArrayList<>(handlers);
        sorted.sort(Comparator.comparingInt(SecurityEventHandler::getOrder));
        return sorted;
    }

    private void logHandlerTopologyOnce(List<SecurityEventHandler> sortedHandlers) {
        if (handlerTopologyLogged.compareAndSet(false, true)) {
            log.info("[SecurityEventProcessor] Registered handlers: {}",
                    sortedHandlers.stream().map(SecurityEventHandler::getName).toList());
        }
    }

    private void recordProcessingMetrics(SecurityEventContext context, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;

        SecurityEventContext.ProcessingMetrics metrics = context.getProcessingMetrics();
        if (metrics == null) {
            metrics = new SecurityEventContext.ProcessingMetrics();
            context.setProcessingMetrics(metrics);
        }

        metrics.setTotalTimeMs(totalTime);
        metrics.setProcessingNode(System.getProperty("node.id", "local"));
    }
}
