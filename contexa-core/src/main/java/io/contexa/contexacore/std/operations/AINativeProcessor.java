package io.contexa.contexacore.std.operations;

import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.UUID;

@Slf4j
final public class AINativeProcessor<T extends DomainContext> implements AICoreOperations<T> {

    private final DistributedSessionManager<T> sessionManager;
    private final RedisDistributedLockService distributedLockService;
    private final DistributedStrategyExecutor<T> distributedStrategyExecutor;
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

    }

    @Override
    public <R extends AIResponse> Mono<R> process(AIRequest<T> request, Class<R> responseType) {
        return doProcess(request, responseType);
    }

    private <R extends AIResponse> Mono<R> doProcess(AIRequest<T> request, Class<R> responseType) {
        String strategyId = generateStrategyId(request, responseType);
        String lockKey = STRATEGIC_LOCK_PREFIX + strategyId;

        return Mono.fromCallable(() -> {
                    if (acquireStrategicLock(lockKey, strategyId)) {
                        throw new AIOperationException("Strategic operation conflict: " + strategyId);
                    }
                    return strategyId;
                })
                .flatMap(id -> {
                    try {
                        String sessionId = sessionManager.createDistributedStrategySession(request, id);
                        String auditId = generateAuditId(request, id);
                        return distributedStrategyExecutor.executeDistributedStrategyAsync(request, responseType, sessionId)
                                .doOnSuccess(result -> {
                                    sessionManager.completeDistributedExecution(sessionId, auditId, request, result, true);
                                })
                                .doOnError(error -> {
                                    handleStrategicFailure(id, request, (Exception) error);
                                })
                                .doFinally(signalType -> {
                                    releaseStrategicLock(lockKey, id);
                                });

                    } catch (Exception e) {
                        handleStrategicFailure(id, request, e);
                        releaseStrategicLock(lockKey, id);
                        return Mono.error(new AIOperationException("Async strategic operation failed: " + id, e));
                    }
                });
    }

    @Override
    public Flux<String> processStream(AIRequest<T> request) {
        return doProcessStream(request);
    }

    private <R extends AIResponse> Flux<String> doProcessStream(AIRequest<T> request) {
        String strategyId = generateStrategyId(request, AIResponse.class);
        String lockKey = STRATEGIC_LOCK_PREFIX + strategyId;

        return Mono.fromCallable(() -> acquireStrategicLock(lockKey, strategyId))
                .flatMapMany(lockFailed -> {
                    if (lockFailed) {
                        return Flux.error(new AIOperationException("Strategic streaming operation conflict: " + strategyId));
                    }

                    String sessionId = sessionManager.createDistributedStrategySession(request, strategyId);
                    String auditId = generateAuditId(request, strategyId);

                    return distributedStrategyExecutor.executeDistributedStrategyStream(
                            request, (Class<R>) AIResponse.class, sessionId, auditId
                    ).doOnComplete(() -> {
                        sessionManager.completeDistributedExecution(sessionId, auditId, request, null, true);
                    }).doOnError(error -> {
                        handleStrategicFailure(strategyId, request, (Exception) error);
                    }).doFinally(signalType -> {
                        releaseStrategicLock(lockKey, strategyId);
                    });
                })
                .onErrorResume(e -> {
                    if (!(e instanceof AIOperationException)) {
                        handleStrategicFailure(strategyId, request, (Exception) e);
                        releaseStrategicLock(lockKey, strategyId);
                        return Flux.error(new AIOperationException("Streaming strategic operation failed: " + strategyId, e));
                    }
                    return Flux.error(e);
                });
    }

    private boolean acquireStrategicLock(String lockKey, String strategyId) {
        try {
            return !distributedLockService.tryLock(lockKey, getNodeId(), STRATEGIC_LOCK_TIMEOUT);
        } catch (Exception e) {
            log.error("Failed to acquire strategic lock: {} - {}", strategyId, e.getMessage());
            return true;
        }
    }

    private void releaseStrategicLock(String lockKey, String strategyId) {
        try {
            distributedLockService.unlock(lockKey, getNodeId());
        } catch (Exception e) {
            log.error("Failed to release strategic lock: {} - {}", strategyId, e.getMessage());
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