package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.handler.strategy.ProcessingStrategy;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

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

        try {
            ProcessingStrategy strategy = selectStrategy(mode);
            long startTime = System.currentTimeMillis();
            ProcessingResult result = strategy.process(context);
            long executionTime = System.currentTimeMillis() - startTime;

            handleProcessingResult(context, result, executionTime);

            return result.isSuccess();

        } catch (Exception e) {
            log.error("[ProcessingExecutionHandler] Error executing processing for event: {}", event.getEventId(), e);
            context.markAsFailed("Processing execution error: " + e.getMessage());
            return false;
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
