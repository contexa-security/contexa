package io.contexa.contexacore.autonomous.orchestrator;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;


@Slf4j
@RequiredArgsConstructor
public class SecurityEventProcessingOrchestrator {

    private final List<SecurityEventHandler> handlers;

    
    public SecurityEventContext process(SecurityEvent event) {
        long startTime = System.currentTimeMillis();

        
        SecurityEventContext context = SecurityEventContext.builder()
            .securityEvent(event)
            .processingStatus(SecurityEventContext.ProcessingStatus.PENDING)
            .createdAt(LocalDateTime.now())
            .build();

        
        context.addMetadata("startTime", startTime);
        context.addMetadata("agentId", "security-plane-agent");
        context.addMetadata("orchestratorVersion", "1.0");

        try {
            
            List<SecurityEventHandler> sortedHandlers = getSortedHandlers();

            log.info("[SecurityEventProcessingOrchestrator] Starting event processing - eventId: {}, handlers: {}",
                event.getEventId(), sortedHandlers.size());

            for (SecurityEventHandler handler : sortedHandlers) {
                if (!executeHandler(handler, context)) {
                    log.info("[SecurityEventProcessingOrchestrator] Processing chain stopped by handler: {}",
                        handler.getName());
                    break;
                }
            }

            
            if (context.getProcessingStatus() != SecurityEventContext.ProcessingStatus.FAILED) {
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

    
    private boolean executeHandler(SecurityEventHandler handler, SecurityEventContext context) {
        
        if (!handler.canHandle(context)) {
            log.debug("[Orchestrator] Handler {} skipped - cannot handle current context",
                handler.getName());
            return true; 
        }

        try {
            long handlerStartTime = System.currentTimeMillis();

            log.info("[SecurityEventProcessingOrchestrator] Executing handler: {} for event: {}",
                handler.getName(), context.getSecurityEvent().getEventId());

            
            boolean continueChain = handler.handle(context);

            
            long handlerTime = System.currentTimeMillis() - handlerStartTime;
            context.addMetadata(handler.getName() + "_executionTime", handlerTime);

            log.info("[SecurityEventProcessingOrchestrator] Handler {} completed in {}ms - continue: {}",
                handler.getName(), handlerTime, continueChain);

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

    
    private void recordProcessingMetrics(SecurityEventContext context, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;

        SecurityEventContext.ProcessingMetrics metrics = context.getProcessingMetrics();
        if (metrics == null) {
            metrics = new SecurityEventContext.ProcessingMetrics();
            context.setProcessingMetrics(metrics);
        }

        metrics.setTotalTimeMs(totalTime);
        metrics.setProcessingNode(System.getProperty("node.id", "local"));

        context.addMetadata("totalProcessingTime", totalTime);
        context.addMetadata("completedAt", LocalDateTime.now());

        log.info("[Orchestrator] Event processing completed - eventId: {}, status: {}, totalTime: {}ms",
            context.getSecurityEvent().getEventId(),
            context.getProcessingStatus(),
            totalTime);
    }

    
    public void addHandler(SecurityEventHandler handler) {
        if (handler != null && !handlers.contains(handler)) {
            handlers.add(handler);
            log.info("[Orchestrator] Handler added: {}", handler.getName());
        }
    }

    
    public void removeHandler(SecurityEventHandler handler) {
        if (handler != null && handlers.remove(handler)) {
            log.info("[Orchestrator] Handler removed: {}", handler.getName());
        }
    }

    
    public List<String> getHandlerNames() {
        return getSortedHandlers().stream()
            .map(SecurityEventHandler::getName)
            .toList();
    }
}