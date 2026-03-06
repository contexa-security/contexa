package io.contexa.contexacore.std.operations;

import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;

import java.util.Map;
import java.util.UUID;

@Slf4j
public class DistributedSessionManager<T extends DomainContext> {

    private final AuditLogger auditLogger;
    private final ApplicationEventPublisher eventPublisher;

    @Autowired
    public DistributedSessionManager(AuditLogger auditLogger,
                                     ApplicationEventPublisher eventPublisher) {
        this.auditLogger = auditLogger;
        this.eventPublisher = eventPublisher;
    }

    public String startAudit(AIRequest<T> request) {
        return auditLogger.startAudit(request);
    }

    public String createDistributedStrategySession(AIRequest<T> request, String strategyId) {
        try {
            String sessionId = UUID.randomUUID().toString();

            Map<String, Object> initialContext = prepareStrategyContext(request, strategyId);

            publishSessionCreationEvent(sessionId, strategyId, request);
            
            return sessionId;
            
        } catch (Exception e) {
            log.error("Failed to create distributed strategy session for strategy: {}", strategyId, e);
            throw new AIOperationException("Session creation failed", e);
        }
    }

    public <R extends AIResponse> void completeDistributedExecution(String sessionId, String auditId,
                                                                     AIRequest<T> request, R result,
                                                                    boolean success) {
        try {
            if (success) {
                auditLogger.completeAudit(auditId, request, result);
            } else {
                auditLogger.failAudit(auditId, request, new Exception("Strategy execution failed"));
            }
        } catch (Exception e) {
            log.error("Failed to complete distributed execution for session: {}", sessionId, e);
        }
    }

    private Map<String, Object> prepareStrategyContext(AIRequest<T> request, String strategyId) {
        return Map.of(
            "strategyId", strategyId,
            "requestType", request.getClass().getSimpleName(),
            "creationTime", System.currentTimeMillis(),
            "nodeId", getNodeId()
        );
    }

    private String getNodeId() {
        return System.getProperty("node.id", "node-" + UUID.randomUUID().toString().substring(0, 8));
    }

    private void publishSessionCreationEvent(String sessionId, String strategyId, AIRequest<T> request) {
        Map<String, Object> eventPayload = Map.of(
                "sessionId", sessionId,
                "strategyId", strategyId,
                "requestId", request.getRequestId() != null ? request.getRequestId() : "unknown",
                "creationTime", System.currentTimeMillis()
        );
        eventPublisher.publishEvent(eventPayload);
    }

}