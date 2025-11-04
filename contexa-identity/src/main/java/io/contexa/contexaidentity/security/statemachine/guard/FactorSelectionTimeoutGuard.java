package io.contexa.contexaidentity.security.statemachine.guard;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * 팩터 선택 타임아웃 확인 Guard
 *
 * SelectFactorAction에서 설정한 factorSelectedAt 속성을 확인하여
 * 팩터 선택 후 일정 시간이 경과했는지 검증합니다.
 *
 * Phase 2.4: factorSelectedAt 타임아웃 검증
 */
@Slf4j
@Component
public class FactorSelectionTimeoutGuard extends AbstractMfaStateGuard {

    /**
     * 팩터 선택 타임아웃 (밀리초)
     * 기본값: 5분 (300,000ms)
     */
    private static final long DEFAULT_SELECTION_TIMEOUT_MS = 5 * 60 * 1000L;

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();

        // factorSelectedAt 속성 확인
        Object selectedAtObj = factorContext.getAttribute("factorSelectedAt");

        if (!(selectedAtObj instanceof Long)) {
            log.debug("[FactorSelectionTimeoutGuard] factorSelectedAt not set for session: {}, allowing transition",
                    sessionId);
            return true; // 선택 시간이 설정되지 않았으면 허용
        }

        Long factorSelectedAt = (Long) selectedAtObj;
        long currentTime = System.currentTimeMillis();
        long elapsedTime = currentTime - factorSelectedAt;
        long timeoutMs = getSelectionTimeoutMs(factorContext);

        boolean withinTimeout = elapsedTime < timeoutMs;

        if (!withinTimeout) {
            log.warn("[FactorSelectionTimeoutGuard] Factor selection timeout exceeded for session: {}, " +
                            "elapsed: {}ms, timeout: {}ms",
                    sessionId, elapsedTime, timeoutMs);
        } else {
            log.debug("[FactorSelectionTimeoutGuard] Factor selection within timeout for session: {}, " +
                            "elapsed: {}ms, remaining: {}ms",
                    sessionId, elapsedTime, (timeoutMs - elapsedTime));
        }

        return withinTimeout;
    }

    /**
     * 팩터 선택 타임아웃 설정 가져오기
     *
     * @param factorContext FactorContext
     * @return 타임아웃 (밀리초)
     */
    private long getSelectionTimeoutMs(FactorContext factorContext) {
        // 커스텀 타임아웃이 설정되어 있으면 사용
        Object customTimeoutObj = factorContext.getAttribute("factorSelectionTimeoutMs");
        if (customTimeoutObj instanceof Long) {
            return (Long) customTimeoutObj;
        }
        if (customTimeoutObj instanceof Integer) {
            return ((Integer) customTimeoutObj).longValue();
        }

        return DEFAULT_SELECTION_TIMEOUT_MS;
    }

    @Override
    public String getFailureReason() {
        return "Factor selection timeout exceeded";
    }

    @Override
    public String getGuardName() {
        return "FactorSelectionTimeoutGuard";
    }

    /**
     * 남은 팩터 선택 시간 계산 (밀리초)
     *
     * @param factorContext FactorContext
     * @return 남은 시간 (밀리초), 선택 시간이 설정되지 않았으면 타임아웃 전체 시간 반환
     */
    public long getRemainingSelectionTimeMs(FactorContext factorContext) {
        Object selectedAtObj = factorContext.getAttribute("factorSelectedAt");

        if (!(selectedAtObj instanceof Long)) {
            return getSelectionTimeoutMs(factorContext);
        }

        Long factorSelectedAt = (Long) selectedAtObj;
        long currentTime = System.currentTimeMillis();
        long elapsedTime = currentTime - factorSelectedAt;
        long timeoutMs = getSelectionTimeoutMs(factorContext);

        return Math.max(0, timeoutMs - elapsedTime);
    }

    /**
     * 팩터 선택 타임아웃 여부 확인
     *
     * @param factorContext FactorContext
     * @return 타임아웃 여부
     */
    public boolean isSelectionTimedOut(FactorContext factorContext) {
        return !doEvaluate(null, factorContext);
    }

    /**
     * 커스텀 팩터 선택 타임아웃 설정
     *
     * @param factorContext FactorContext
     * @param timeoutMs 타임아웃 (밀리초)
     */
    public void setSelectionTimeout(FactorContext factorContext, long timeoutMs) {
        factorContext.setAttribute("factorSelectionTimeoutMs", timeoutMs);
        log.debug("[FactorSelectionTimeoutGuard] Custom selection timeout set to {}ms for session: {}",
                timeoutMs, factorContext.getMfaSessionId());
    }
}
