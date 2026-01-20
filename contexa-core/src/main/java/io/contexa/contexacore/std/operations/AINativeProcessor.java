package io.contexa.contexacore.std.operations;

import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
final public class AINativeProcessor<T extends DomainContext> implements AICoreOperations<T> {
    
    
    private final DistributedSessionManager<T> sessionManager;
    private final RedisDistributedLockService distributedLockService;

    
    private final DistributedStrategyExecutor<T> distributedStrategyExecutor; 
    
    
    private final AtomicLong totalStrategicOperations = new AtomicLong(0);
    private final AtomicLong successfulStrategicOperations = new AtomicLong(0);
    private final AtomicLong failedStrategicOperations = new AtomicLong(0);
    
    
    private static final Duration STRATEGIC_LOCK_TIMEOUT = Duration.ofMinutes(30);
    private static final String STRATEGIC_LOCK_PREFIX = "ai:strategy:master:";
    
    
    private final String nodeId;
    
    @Autowired
    public AINativeProcessor(DistributedSessionManager<T> sessionManager,
                             RedisDistributedLockService distributedLockService,
                             DistributedStrategyExecutor<T> distributedStrategyExecutor) {
        this.sessionManager = sessionManager;
        this.distributedLockService = distributedLockService;
        this.distributedStrategyExecutor = distributedStrategyExecutor; 
        
        
        this.nodeId = System.getProperty("node.id", "master-" + UUID.randomUUID().toString().substring(0, 8));

        log.info("AI Native IAM Operations Master Brain initialized - Node ID: {}", this.nodeId);
        log.info("DistributedStrategyExecutor integrated - Complete delegation established");
        log.info("Natural Order: AINativeIAMOperations → DistributedStrategyExecutor → DiagnosisStrategyRegistry");
    }

    @Override
    public <R extends AIResponse> Mono<R> process(AIRequest<T> request, Class<R> responseType) {
        return executeWithAuditAsync(request, responseType);
    }
    
    private <R extends AIResponse> Mono<R> executeWithAuditAsync(AIRequest<T> request, Class<R> responseType) {
        String strategyId = generateStrategyId(request, responseType);
        String lockKey = STRATEGIC_LOCK_PREFIX + strategyId;
        
        log.info("Master Brain: Async strategic operation initiated - {}", strategyId);
        totalStrategicOperations.incrementAndGet();
        
        return Mono.fromCallable(() -> {
            if (!acquireStrategicLock(lockKey, strategyId)) {
                throw new AIOperationException("Strategic operation conflict: " + strategyId);
            }
            return strategyId;
        })
        .flatMap(id -> {
            try {
                String sessionId = sessionManager.createDistributedStrategySession(request, id);
                String auditId = generateAuditId(request, id);
                
                log.debug("Master Brain: Async delegating to DistributedStrategyExecutor - session: {}", sessionId);
                
                
                return distributedStrategyExecutor.executeDistributedStrategyAsync(
                    request, responseType, sessionId, auditId
                )
                .doOnSuccess(result -> {
                    
                    sessionManager.completeDistributedExecution(sessionId, auditId, request, result, true);
                    successfulStrategicOperations.incrementAndGet();
                    log.info("Master Brain: Async strategic operation completed successfully - {}", id);
                })
                .doOnError(error -> {
                    handleStrategicFailure(id, request, (Exception) error);
                    failedStrategicOperations.incrementAndGet();
                })
                .doFinally(signalType -> {
                    releaseStrategicLock(lockKey, id);
                });
                
            } catch (Exception e) {
                handleStrategicFailure(id, request, e);
                failedStrategicOperations.incrementAndGet();
                releaseStrategicLock(lockKey, id);
                return Mono.error(new AIOperationException("Async strategic operation failed: " + id, e));
            }
        });
    }

    @Override
    public Flux<String> processStream(AIRequest<T> request) {
        log.info("스트리밍 요청 시작 - 실제 스트리밍 방식: {}", request.getRequestId());
        return executeStreamWithAudit(request, AIResponse.class);
    }

    private <R extends AIResponse> Flux<String> executeStreamWithAudit(AIRequest<T> request, Class<R> responseType) {
        String strategyId = generateStrategyId(request, responseType);
        String lockKey = STRATEGIC_LOCK_PREFIX + strategyId;
        
        log.info("Master Brain: Streaming strategic operation initiated - {}", strategyId);
        totalStrategicOperations.incrementAndGet();
        
        if (!acquireStrategicLock(lockKey, strategyId)) {
            return Flux.error(new AIOperationException("Strategic streaming operation conflict: " + strategyId));
        }
        
        try {
            String sessionId = sessionManager.createDistributedStrategySession(request, strategyId);
            String auditId = generateAuditId(request, strategyId);
            
            log.debug("Master Brain: Delegating to DistributedStrategyExecutor for streaming - session: {}", sessionId);
            
            return distributedStrategyExecutor.executeDistributedStrategyStream(
                request, responseType, sessionId, auditId
            ).doOnComplete(() -> {
                sessionManager.completeDistributedExecution(sessionId, auditId, request, null, true);
                successfulStrategicOperations.incrementAndGet();
                log.info("Master Brain: Streaming strategic operation completed successfully - {}", strategyId);
            }).doOnError(error -> {
                handleStrategicFailure(strategyId, request, (Exception) error);
                failedStrategicOperations.incrementAndGet();
            }).doFinally(signalType -> {
                releaseStrategicLock(lockKey, strategyId);
            });
            
        } catch (Exception e) {
            handleStrategicFailure(strategyId, request, e);
            failedStrategicOperations.incrementAndGet();
            releaseStrategicLock(lockKey, strategyId);
            return Flux.error(new AIOperationException("Streaming strategic operation failed: " + strategyId, e));
        }
    }

    @Override
    public <R extends AIResponse> Flux<R> executeStreamTyped(AIRequest<T> request, Class<R> responseType) {
        return null;
    }

    @Override
    public <R extends AIResponse> Mono<List<R>> executeBatch(List<AIRequest<T>> requests, Class<R> responseType) {
        List<Mono<R>> asyncRequests = requests.stream()
            .map(request -> executeWithAuditAsync(request, responseType))
            .toList();
        return Flux.merge(asyncRequests)
            .collectList();
    }
    
    @Override
    public <T1 extends DomainContext, T2 extends DomainContext> 
    Mono<AIResponse> executeMixed(List<AIRequest<T1>> requests1, List<AIRequest<T2>> requests2) {
        return Mono.error(new UnsupportedOperationException("Mixed requests not supported in IAM domain"));
    }
    
    private boolean acquireStrategicLock(String lockKey, String strategyId) {
        try {
            return distributedLockService.tryLock(lockKey, getNodeId(), STRATEGIC_LOCK_TIMEOUT);
        } catch (Exception e) {
            log.error("Failed to acquire strategic lock: {} - {}", strategyId, e.getMessage());
            return false;
        }
    }

    private void releaseStrategicLock(String lockKey, String strategyId) {
        try {
            distributedLockService.unlock(lockKey, getNodeId());
        } catch (Exception e) {
            log.warn("Failed to release strategic lock: {} - {}", strategyId, e.getMessage());
        }
    }
    
    private void handleStrategicFailure(String strategyId, AIRequest<T> request, Exception error) {
        log.error("Strategic operation failed: {} - {}", strategyId, error.getMessage(), error);
    }
    
    private String generateStrategyId(AIRequest<T> request, Class<?> responseType) {
        return String.format("strategy-%s-%s-%s", 
            request.getClass().getSimpleName(),
            responseType.getSimpleName(),
            UUID.randomUUID().toString().substring(0, 8));
    }
    
    private String generateAuditId(AIRequest<T> request, String strategyId) {
        return String.format("audit-%s-%s", strategyId, System.currentTimeMillis());
    }
    
    private String getNodeId() {
        return this.nodeId;
    }
}