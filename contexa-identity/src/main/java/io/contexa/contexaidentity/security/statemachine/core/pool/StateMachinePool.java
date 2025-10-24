package io.contexa.contexaidentity.security.statemachine.core.pool;

import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe State Machine Pool 구현
 * - 객체 재사용으로 성능 향상
 * - 동시성 제어 및 리소스 관리
 * - 자동 확장/축소 기능
 */
@Slf4j
public class StateMachinePool {

    private final BlockingQueue<PooledStateMachine> availablePool;
    private final Map<String, PooledStateMachine> inUsePool;
    private final StateMachineFactory<MfaState, MfaEvent> factory;
    private final StateMachinePersister<MfaState, MfaEvent, String> persister;

    // Pool 설정
    private final int corePoolSize;
    private final int maxPoolSize;
    private final long keepAliveTime;
    private final TimeUnit keepAliveUnit;

    // 통계 정보
    private final AtomicInteger totalCreated = new AtomicInteger(0);
    private final AtomicInteger currentSize = new AtomicInteger(0);
    private final AtomicLong totalBorrowed = new AtomicLong(0);
    private final AtomicLong totalReturned = new AtomicLong(0);

    // 풀 관리 Executor
    private final ScheduledExecutorService poolMaintenanceExecutor;

    // Semaphore for pool size control
    private final Semaphore poolSemaphore;

    public StateMachinePool(StateMachineFactory<MfaState, MfaEvent> factory,
                            StateMachinePersister<MfaState, MfaEvent, String> persister,
                            int corePoolSize,
                            int maxPoolSize,
                            long keepAliveTime,
                            TimeUnit keepAliveUnit) {
        this.factory = factory;
        this.persister = persister;
        this.corePoolSize = corePoolSize;
        this.maxPoolSize = maxPoolSize;
        this.keepAliveTime = keepAliveTime;
        this.keepAliveUnit = keepAliveUnit;

        this.availablePool = new LinkedBlockingQueue<>();
        this.inUsePool = new ConcurrentHashMap<>();
        this.poolSemaphore = new Semaphore(maxPoolSize, true);

        this.poolMaintenanceExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "StateMachinePool-Maintenance");
            thread.setDaemon(true);
            return thread;
        });

        // 초기 풀 생성
        initializePool();

        // 주기적 유지보수 작업 스케줄링
        scheduleMaintenanceTasks();
    }

    /**
     * State Machine 대여 - 개선된 버전 (메모리 누수 방지)
     */
    public CompletableFuture<PooledStateMachine> borrowStateMachine(String sessionId, long timeout, TimeUnit unit) {
        return CompletableFuture.supplyAsync(() -> {
            boolean acquired = false;
            try {
                // 세마포어 획득 시도
                if (!poolSemaphore.tryAcquire(timeout, unit)) {
                    throw new TimeoutException("Unable to acquire state machine from pool within timeout");
                }
                acquired = true;

                PooledStateMachine pooled = null;

                try {
                    // 1. 사용 가능한 풀에서 가져오기 시도
                    pooled = availablePool.poll();

                    // 2. 없으면 새로 생성 (maxPoolSize 제한 내에서)
                    if (pooled == null && currentSize.get() < maxPoolSize) {
                        pooled = createNewStateMachine();
                    }

                    // 3. 그래도 없으면 대기
                    if (pooled == null) {
                        long remainingTime = unit.toNanos(timeout);
                        long deadline = System.nanoTime() + remainingTime;

                        while (pooled == null && remainingTime > 0) {
                            pooled = availablePool.poll(remainingTime, TimeUnit.NANOSECONDS);
                            remainingTime = deadline - System.nanoTime();
                        }
                    }

                    if (pooled == null) {
                        throw new TimeoutException("No available state machine in pool");
                    }

                    // 4. 상태 준비
                    prepareStateMachine(pooled, sessionId);

                    // 5. 사용 중 풀로 이동
                    pooled.setInUse(true);
                    pooled.setCurrentSessionId(sessionId);
                    inUsePool.put(sessionId, pooled);
                    totalBorrowed.incrementAndGet();

                    log.debug("Borrowed state machine for session: {}, Pool stats - available: {}, inUse: {}",
                            sessionId, availablePool.size(), inUsePool.size());

                    return pooled;

                } catch (Exception e) {
                    // 에러 발생 시 생성된 인스턴스 정리
                    if (pooled != null) {
                        try {
                            destroyStateMachine(pooled);
                        } catch (Exception ex) {
                            log.error("Error destroying state machine after borrow failure", ex);
                        }
                    }
                    throw new CompletionException("Failed to borrow state machine", e);
                }

            } catch (Exception e) {
                // 세마포어 해제 (acquired가 true인 경우만)
                if (acquired) {
                    poolSemaphore.release();
                }
                throw new CompletionException("Failed to acquire pool semaphore", e);
            }
        });
    }

    /**
     * State Machine 반환 - 개선된 버전
     */
    public CompletableFuture<Void> returnStateMachine(String sessionId) {
        return CompletableFuture.runAsync(() -> {
            PooledStateMachine pooled = inUsePool.remove(sessionId);

            if (pooled == null) {
                log.warn("Attempted to return non-existent state machine for session: {}", sessionId);
                return;
            }

            try {
                // 상태 영속화
                if (pooled.getStateMachine() != null && !pooled.getStateMachine().hasStateMachineError()) {
                    persister.persist(pooled.getStateMachine(), sessionId);
                }

                // 상태 머신 리셋
                resetStateMachine(pooled);

                // 유효성 검사
                if (isStateMachineHealthy(pooled)) {
                    pooled.setInUse(false);
                    pooled.setLastReturnedAt(System.currentTimeMillis());
                    // 사용 가능한 풀로 반환
                    if (!availablePool.offer(pooled)) {
                        log.warn("Failed to return state machine to available pool, destroying it");
                        destroyStateMachine(pooled);
                    } else {
                        totalReturned.incrementAndGet();
                    }
                } else {
                    // 문제가 있으면 폐기
                    log.info("Destroying unhealthy state machine for session: {}", sessionId);
                    destroyStateMachine(pooled);
                }

            } catch (Exception e) {
                log.error("Error returning state machine for session: {}", sessionId, e);
                try {
                    destroyStateMachine(pooled);
                } catch (Exception ex) {
                    log.error("Error destroying state machine after return failure", ex);
                }
            } finally {
                // 항상 세마포어 해제
                poolSemaphore.release();
            }

            log.debug("Returned state machine for session: {}, Pool stats - available: {}, inUse: {}",
                    sessionId, availablePool.size(), inUsePool.size());
        });
    }

    /**
     * 초기 풀 생성
     */
    private void initializePool() {
        for (int i = 0; i < corePoolSize; i++) {
            try {
                PooledStateMachine pooled = createNewStateMachine();
                availablePool.offer(pooled);
            } catch (Exception e) {
                log.error("Failed to create initial state machine", e);
            }
        }

        log.info("State machine pool initialized with {} instances", availablePool.size());
    }

    /**
     * 새로운 State Machine 생성
     */
    private PooledStateMachine createNewStateMachine() {
        String machineId = "pool-sm-" + UUID.randomUUID();
        StateMachine<MfaState, MfaEvent> stateMachine = factory.getStateMachine(machineId);

        PooledStateMachine pooled = new PooledStateMachine(stateMachine);
        pooled.setCreatedAt(System.currentTimeMillis());
        pooled.setBorrowCount(0);

        totalCreated.incrementAndGet();
        currentSize.incrementAndGet();

        log.debug("Created new state machine: {}", machineId);
        return pooled;
    }

    /**
     * State Machine 준비 (세션 복원)
     */
    private void prepareStateMachine(PooledStateMachine pooled, String sessionId) throws Exception {
        StateMachine<MfaState, MfaEvent> sm = pooled.getStateMachine();

        if (sm == null) {
            throw new IllegalStateException("StateMachine is null in pool");
        }

        // 기존 상태 정리
        if (sm.getExtendedState() != null && sm.getExtendedState().getVariables() != null) {
            sm.getExtendedState().getVariables().clear();
        }

        // State Machine 재시작으로 깨끗한 상태 보장
        if (sm.isComplete() || sm.hasStateMachineError()) {
            sm.stop();
            Thread.sleep(50);
        }

        // 이전 상태 복원 시도
        boolean restored = false;
        try {
            persister.restore(sm, sessionId);
            restored = true;
            log.debug("Restored state for session: {}", sessionId);
        } catch (Exception e) {
            log.debug("No persisted state found for session: {} - Starting fresh", sessionId);
        }

        // State Machine 시작 (필요한 경우만)
        if (!sm.isComplete() && (sm.getState() == null || !restored)) {
            sm.start();

            // 초기화 완료 대기 (타임아웃 추가)
            long startTime = System.currentTimeMillis();
            while (sm.getExtendedState() == null ||
                    sm.getExtendedState().getVariables() == null) {

                if (System.currentTimeMillis() - startTime > 5000) {
                    throw new TimeoutException("State Machine initialization timeout");
                }

                Thread.sleep(100);
            }
        }

        // 사용 정보 업데이트
        pooled.setLastBorrowedAt(System.currentTimeMillis());
        pooled.setBorrowCount(pooled.getBorrowCount() + 1);
        pooled.setCurrentSessionId(sessionId);
    }

    /**
     * State Machine 리셋
     */
    private void resetStateMachine(PooledStateMachine pooled) {
        StateMachine<MfaState, MfaEvent> sm = pooled.getStateMachine();

        // Extended state 클리어
        sm.getExtendedState().getVariables().clear();

        // 세션 정보 클리어
        pooled.setCurrentSessionId(null);
        pooled.setLastReturnedAt(System.currentTimeMillis());

        // 상태를 초기 상태로 리셋
        if (sm.isComplete()) {
            sm.stop();
        }
    }

    /**
     * State Machine 건강 상태 확인
     */
    private boolean isStateMachineHealthy(PooledStateMachine pooled) {
        StateMachine<MfaState, MfaEvent> sm = pooled.getStateMachine();

        // 에러 상태 확인
        if (sm.hasStateMachineError()) {
            return false;
        }

        // 사용 횟수 제한 확인 (메모리 누수 방지)
        if (pooled.getBorrowCount() > 1000) {
            return false;
        }

        // 생성 시간 확인 (오래된 인스턴스 교체)
        long ageMinutes = TimeUnit.MILLISECONDS.toMinutes(
                System.currentTimeMillis() - pooled.getCreatedAt()
        );

        return ageMinutes < 60; // 1시간 이상된 인스턴스는 교체
    }

    /**
     * State Machine 폐기
     */
    private void destroyStateMachine(PooledStateMachine pooled) {
        try {
            StateMachine<MfaState, MfaEvent> sm = pooled.getStateMachine();
            if (!sm.isComplete()) {
                sm.stop();
            }
            currentSize.decrementAndGet();
            log.debug("Destroyed state machine: {}", sm.getId());
        } catch (Exception e) {
            log.error("Error destroying state machine", e);
        }
    }

    /**
     * 주기적 유지보수 작업 스케줄링
     */
    private void scheduleMaintenanceTasks() {
        // 1. 유휴 상태 머신 정리
        poolMaintenanceExecutor.scheduleWithFixedDelay(
                this::cleanupIdleStateMachines,
                keepAliveTime,
                keepAliveTime,
                keepAliveUnit
        );

        // 2. 풀 크기 조정
        poolMaintenanceExecutor.scheduleWithFixedDelay(
                this::adjustPoolSize,
                1,
                1,
                TimeUnit.MINUTES
        );

        // 3. 건강 상태 확인
        poolMaintenanceExecutor.scheduleWithFixedDelay(
                this::healthCheck,
                5,
                5,
                TimeUnit.MINUTES
        );

        // 4. 통계 로깅
        poolMaintenanceExecutor.scheduleWithFixedDelay(
                this::logStatistics,
                1,
                1,
                TimeUnit.MINUTES
        );
    }

    /**
     * 유휴 상태 머신 정리
     */
    private void cleanupIdleStateMachines() {
        try {
            int removed = 0;
            long idleThreshold = keepAliveUnit.toMillis(keepAliveTime);

            while (availablePool.size() > corePoolSize) {
                PooledStateMachine pooled = availablePool.peek();

                if (pooled != null && isIdleTooLong(pooled, idleThreshold)) {
                    if (availablePool.remove(pooled)) {
                        destroyStateMachine(pooled);
                        removed++;
                    }
                } else {
                    break;
                }
            }

            if (removed > 0) {
                log.info("Cleaned up {} idle state machines", removed);
            }
        } catch (Exception e) {
            log.error("Error during idle cleanup", e);
        }
    }

    /**
     * 풀 크기 조정
     */
    private void adjustPoolSize() {
        try {
            int availableSize = availablePool.size();
            int inUseSize = inUsePool.size();
            int totalSize = availableSize + inUseSize;

            // 사용률 계산
            double utilizationRate = totalSize > 0 ? (double) inUseSize / totalSize : 0;

            // 고사용률(80% 이상)이면 풀 확장
            if (utilizationRate > 0.8 && totalSize < maxPoolSize) {
                int toCreate = Math.min(corePoolSize, maxPoolSize - totalSize);
                for (int i = 0; i < toCreate; i++) {
                    try {
                        PooledStateMachine pooled = createNewStateMachine();
                        availablePool.offer(pooled);
                    } catch (Exception e) {
                        log.error("Failed to expand pool", e);
                        break;
                    }
                }
                log.info("Expanded pool by {} instances due to high utilization ({}%)",
                        toCreate, Math.round(utilizationRate * 100));
            }

            // 저사용률(20% 미만)이면 풀 축소
            else if (utilizationRate < 0.2 && totalSize > corePoolSize) {
                int toRemove = Math.min(availableSize / 2, totalSize - corePoolSize);
                for (int i = 0; i < toRemove; i++) {
                    PooledStateMachine pooled = availablePool.poll();
                    if (pooled != null) {
                        destroyStateMachine(pooled);
                    }
                }
                if (toRemove > 0) {
                    log.info("Shrunk pool by {} instances due to low utilization ({}%)",
                            toRemove, Math.round(utilizationRate * 100));
                }
            }
        } catch (Exception e) {
            log.error("Error adjusting pool size", e);
        }
    }

    /**
     * 건강 상태 확인
     */
    private void healthCheck() {
        try {
            // 사용 중인 상태 머신 중 오래된 것 확인
            long staleThreshold = TimeUnit.HOURS.toMillis(1);

            inUsePool.forEach((sessionId, pooled) -> {
                long borrowDuration = System.currentTimeMillis() - pooled.getLastBorrowedAt();

                if (borrowDuration > staleThreshold) {
                    log.warn("State machine for session {} has been borrowed for {} minutes",
                            sessionId, TimeUnit.MILLISECONDS.toMinutes(borrowDuration));
                }
            });

            // 사용 가능한 풀의 건강 상태 확인
            availablePool.removeIf(pooled -> !isStateMachineHealthy(pooled));

        } catch (Exception e) {
            log.error("Error during health check", e);
        }
    }

    /**
     * 통계 로깅
     */
    private void logStatistics() {
        PoolStatistics stats = getStatistics();
        log.info("State Machine Pool Statistics: {}", stats);
    }

    /**
     * 유휴 시간 확인
     */
    private boolean isIdleTooLong(PooledStateMachine pooled, long threshold) {
        long idleTime = System.currentTimeMillis() - pooled.getLastReturnedAt();
        return idleTime > threshold;
    }

    /**
     * 풀 통계 조회
     */
    public PoolStatistics getStatistics() {
        return PoolStatistics.builder()
                .totalCreated(totalCreated.get())
                .currentSize(currentSize.get())
                .availableSize(availablePool.size())
                .inUseSize(inUsePool.size())
                .totalBorrowed(totalBorrowed.get())
                .totalReturned(totalReturned.get())
                .utilizationRate(calculateUtilizationRate())
                .build();
    }

    /**
     * 사용률 계산
     */
    private double calculateUtilizationRate() {
        int total = availablePool.size() + inUsePool.size();
        return total > 0 ? (double) inUsePool.size() / total : 0;
    }

    /**
     * 풀 종료 - 개선된 버전
     */
    public void shutdown() {
        log.info("Shutting down state machine pool");

        poolMaintenanceExecutor.shutdown();

        // 사용 중인 State Machine들 대기
        int waitAttempts = 10;
        while (!inUsePool.isEmpty() && waitAttempts > 0) {
            log.info("Waiting for {} in-use state machines to be returned...", inUsePool.size());
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            waitAttempts--;
        }

        // 강제 정리
        inUsePool.values().forEach(this::destroyStateMachine);
        inUsePool.clear();

        // 사용 가능한 State Machine 정리
        PooledStateMachine pooled;
        while ((pooled = availablePool.poll()) != null) {
            destroyStateMachine(pooled);
        }

        try {
            if (!poolMaintenanceExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                poolMaintenanceExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            poolMaintenanceExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        log.info("State machine pool shutdown complete");
    }

    /**
     * 풀 통계 정보
     */
    @lombok.Builder
    @lombok.Getter
    @lombok.ToString
    public static class PoolStatistics {
        private final int totalCreated;
        private final int currentSize;
        private final int availableSize;
        private final int inUseSize;
        private final long totalBorrowed;
        private final long totalReturned;
        private final double utilizationRate;
    }
}