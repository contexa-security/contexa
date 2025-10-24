package io.contexa.contexaidentity.security.statemachine.core.pool;

import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.Getter;
import lombok.Setter;
import org.springframework.statemachine.StateMachine;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * 풀링된 State Machine 래퍼
 * - State Machine 인스턴스와 메타데이터 관리
 * - 사용 통계 및 상태 추적
 */
@Getter
@Setter
public class PooledStateMachine {

    private final StateMachine<MfaState, MfaEvent> stateMachine;
    private final String poolId;

    // 생명주기 정보
    private long createdAt;
    private long lastBorrowedAt;
    private long lastReturnedAt;

    // 사용 정보
    private String currentSessionId;
    private int borrowCount;
    private final AtomicInteger errorCount = new AtomicInteger(0);

    // 상태 정보
    private volatile boolean healthy = true;
    private volatile boolean inUse = false;

    public PooledStateMachine(StateMachine<MfaState, MfaEvent> stateMachine) {
        this.stateMachine = stateMachine;
        this.poolId = "pooled-" + stateMachine.getId();
        this.createdAt = System.currentTimeMillis();
    }

    /**
     * 에러 카운트 증가
     */
    public void incrementErrorCount() {
        errorCount.incrementAndGet();
    }

    /**
     * 에러 카운트 리셋
     */
    public void resetErrorCount() {
        errorCount.set(0);
    }

    /**
     * 사용 연령 계산 (분)
     */
    public long getAgeInMinutes() {
        return (System.currentTimeMillis() - createdAt) / (1000 * 60);
    }

    /**
     * 마지막 사용 시간 계산 (분)
     */
    public long getIdleTimeInMinutes() {
        long lastUsed = Math.max(lastBorrowedAt, lastReturnedAt);
        return (System.currentTimeMillis() - lastUsed) / (1000 * 60);
    }

    /**
     * 건강 상태 확인
     */
    public boolean isHealthy() {
        if (!healthy) {
            return false;
        }

        // State Machine 에러 확인
        if (stateMachine.hasStateMachineError()) {
            healthy = false;
            return false;
        }

        // 에러 횟수 확인
        if (errorCount.get() > 10) {
            healthy = false;
            return false;
        }

        return true;
    }

    @Override
    public String toString() {
        return String.format("PooledStateMachine[id=%s, inUse=%s, sessionId=%s, borrowCount=%d, age=%dm]",
                poolId, inUse, currentSessionId, borrowCount, getAgeInMinutes());
    }
}
