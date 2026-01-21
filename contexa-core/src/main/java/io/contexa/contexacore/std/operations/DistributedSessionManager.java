package io.contexa.contexacore.std.operations;

import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.components.event.CleanupResult;
import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class DistributedSessionManager<T extends DomainContext> {
    
    private final RedisEventPublisher eventPublisher;
    private final AuditLogger auditLogger;
    
    private final Map<String, String> activeStrategySessions = new ConcurrentHashMap<>();
    
    @Autowired
    public DistributedSessionManager(RedisEventPublisher eventPublisher, AuditLogger auditLogger) {
        this.eventPublisher = eventPublisher;
        this.auditLogger = auditLogger;
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
            
            Map<String, Object> completionData = Map.of(
                "success", success,
                "completionTime", System.currentTimeMillis(),
                "resultType", result != null ? result.getClass().getSimpleName() : "null"
            );
            
            updateSessionState(sessionId, "COMPLETED", completionData);

            AIExecutionMetrics metrics = createExecutionMetrics(sessionId, success);
            saveExecutionMetrics(sessionId, metrics);
            publishExecutionCompletionEvent(sessionId, request, success);

        } catch (Exception e) {
            log.error("Failed to complete distributed execution for session: {}", sessionId, e);
        }
    }

    public void handleDistributedExecutionFailure(String sessionId, AIRequest<T> request,
                                                 Exception error, String strategyId) {
        try {
            
            Map<String, Object> failureData = Map.of(
                "error", error.getMessage(),
                "failureTime", System.currentTimeMillis(),
                "strategyId", strategyId
            );
            
            updateSessionState(sessionId, "FAILED", failureData);

            publishExecutionFailureEvent(sessionId, request, error);
            
            log.error("Distributed execution failed for session: {} with error: {}", sessionId, error.getMessage());
            
        } catch (Exception e) {
            log.error("Failed to handle execution failure for session: {}", sessionId, e);
        }
    }

    public void cleanupDistributedExecution(String strategyId, String sessionId, String lockKey, String nodeId) {
        try {
            
            activeStrategySessions.remove(strategyId);

            publishCleanupEvent(strategyId, sessionId);

        } catch (Exception e) {
            log.error("Failed to cleanup distributed execution for strategy: {}", strategyId, e);
        }
    }

    public CleanupResult cleanupInactiveSessions(Duration inactiveThreshold) {
        try {
            List<String> cleanedSessions = new ArrayList<>();
            List<String> failedCleanups = new ArrayList<>();

            Set<String> inactiveSessions = getInactiveSessions(inactiveThreshold);
            
            for (String sessionId : inactiveSessions) {
                try {
                    
                    cleanupSession(sessionId);
                    cleanedSessions.add(sessionId);
                    
                } catch (Exception e) {
                    log.warn("Failed to cleanup session: {}", sessionId, e);
                    failedCleanups.add(sessionId);
                }
            }

            publishCleanupResultEvent(cleanedSessions, failedCleanups);
            
            return new CleanupResult(cleanedSessions, failedCleanups, System.currentTimeMillis());
            
        } catch (Exception e) {
            log.error("Failed to cleanup inactive sessions", e);
            return CleanupResult.error("Cleanup operation failed: " + e.getMessage());
        }
    }

    private void updateSessionState(String sessionId, String phase, Map<String, Object> phaseData) {
        try {

            eventPublisher.publishEvent("ai:strategy:phase:updated", Map.of(
                "sessionId", sessionId,
                "phase", phase,
                "timestamp", System.currentTimeMillis(),
                "phaseData", phaseData
            ));
            
        } catch (Exception e) {
            log.warn("Failed to update session state for {}: {}", sessionId, e.getMessage());
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
    
    private AIExecutionMetrics createExecutionMetrics(String sessionId, boolean success) {
        
        return new AIExecutionMetrics(sessionId, getNodeId(), System.currentTimeMillis(), success);
    }
    
    private void saveExecutionMetrics(String sessionId, AIExecutionMetrics metrics) {
        try {
            
                    } catch (Exception e) {
            log.warn("Failed to save execution metrics for session: {}", sessionId, e);
        }
    }
    
    private Set<String> getInactiveSessions(Duration inactiveThreshold) {
        
        return Set.of();
    }
    
    private void cleanupSession(String sessionId) {
        
            }
    
    private String getNodeId() {
        return System.getProperty("node.id", "node-" + UUID.randomUUID().toString().substring(0, 8));
    }

    private void publishSessionCreationEvent(String sessionId, String strategyId, AIRequest<T> request) {
        eventPublisher.publishEvent("ai:strategy:session:created", Map.of(
            "sessionId", sessionId,
            "strategyId", strategyId,
            "requestType", request.getClass().getSimpleName(),
            "timestamp", System.currentTimeMillis()
        ));
    }
    
    private void publishExecutionCompletionEvent(String sessionId, AIRequest<T> request, boolean success) {
        eventPublisher.publishEvent("ai:strategy:execution:completed", Map.of(
            "sessionId", sessionId,
            "requestType", request.getClass().getSimpleName(),
            "success", success,
            "timestamp", System.currentTimeMillis()
        ));
    }
    
    private void publishExecutionFailureEvent(String sessionId, AIRequest<T> request, Exception error) {
        eventPublisher.publishEvent("ai:strategy:execution:failed", Map.of(
            "sessionId", sessionId,
            "requestType", request.getClass().getSimpleName(),
            "error", error.getMessage(),
            "timestamp", System.currentTimeMillis()
        ));
    }
    
    private void publishCleanupEvent(String strategyId, String sessionId) {
        eventPublisher.publishEvent("ai:strategy:cleanup:completed", Map.of(
            "strategyId", strategyId,
            "sessionId", sessionId,
            "timestamp", System.currentTimeMillis()
        ));
    }
    
    private void publishCleanupResultEvent(List<String> cleanedSessions, List<String> failedCleanups) {
        eventPublisher.publishEvent("ai:strategy:cleanup:result", Map.of(
            "cleanedSessions", cleanedSessions,
            "failedCleanups", failedCleanups,
            "totalCleaned", cleanedSessions.size(),
            "totalFailed", failedCleanups.size(),
            "timestamp", System.currentTimeMillis()
        ));
    }

    public static class AIExecutionMetrics {
        private final String sessionId;
        private final String nodeId;
        private final long executionTime;
        private final boolean success;
        
        public AIExecutionMetrics(String sessionId, String nodeId, long executionTime, boolean success) {
            this.sessionId = sessionId;
            this.nodeId = nodeId;
            this.executionTime = executionTime;
            this.success = success;
        }

        public String getSessionId() { return sessionId; }
        public String getNodeId() { return nodeId; }
        public long getExecutionTime() { return executionTime; }
        public boolean isSuccess() { return success; }
    }
} 