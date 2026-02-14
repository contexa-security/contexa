package io.contexa.contexaidentity.security.statemachine.guard;

import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class RetryLimitGuard extends AbstractMfaStateGuard {

    private final MfaSettings mfaSettings;

    public RetryLimitGuard(MfaSettings mfaSettings) {
        this.mfaSettings = mfaSettings;
    }

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();
        int currentRetryCount = factorContext.getRetryCount();
        int maxRetries = mfaSettings.getMaxRetryAttempts();

        String currentFactor = factorContext.getCurrentProcessingFactor() != null ?
                factorContext.getCurrentProcessingFactor().name() : null;
        if (currentFactor != null) {
            Integer factorRetryCount = getFactorRetryCount(factorContext, currentFactor);

            if (factorRetryCount >= maxRetries) {
                log.error("Factor {} retry limit exceeded for session: {}",
                        currentFactor, sessionId);
                return false;
            }
        }

        boolean withinLimit = currentRetryCount < maxRetries;

        if (!withinLimit) {
            log.error("Total retry limit exceeded for session: {}", sessionId);
        }

        return withinLimit;
    }

    private Integer getFactorRetryCount(FactorContext factorContext, String factorType) {
        String key = "retryCount_" + factorType;
        Object retryCount = factorContext.getAttribute(key);

        if (retryCount instanceof Integer) {
            return (Integer) retryCount;
        }

        return 0;
    }

    @Override
    public String getFailureReason() {
        return "Maximum retry attempts exceeded";
    }

    @Override
    public String getGuardName() {
        return "RetryLimitGuard";
    }
}
