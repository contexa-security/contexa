package io.contexa.contexaidentity.security.statemachine.guard;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class FactorSelectionTimeoutGuard extends AbstractMfaStateGuard {

    private static final long DEFAULT_SELECTION_TIMEOUT_MS = 5 * 60 * 1000L;

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();
        Object selectedAtObj = factorContext.getAttribute(FactorContextAttributes.Timestamps.FACTOR_SELECTED_AT);

        if (!(selectedAtObj instanceof Long factorSelectedAt)) {
            return true;
        }

        long currentTime = System.currentTimeMillis();
        long elapsedTime = currentTime - factorSelectedAt;
        long timeoutMs = getSelectionTimeoutMs(factorContext);
        boolean withinTimeout = elapsedTime < timeoutMs;

        if (!withinTimeout) {
            log.warn("[FactorSelectionTimeoutGuard] Factor selection timeout exceeded for session: {}, " +
                            "elapsed: {}ms, timeout: {}ms",
                    sessionId, elapsedTime, timeoutMs);
        }

        return withinTimeout;
    }

    private long getSelectionTimeoutMs(FactorContext factorContext) {

        Object customTimeoutObj = factorContext.getAttribute(FactorContextAttributes.StateControl.FACTOR_SELECTION_TIMEOUT_MS);
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

}
