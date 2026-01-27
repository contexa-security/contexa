package io.contexa.contexaidentity.security.statemachine.guard;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class RetryLimitGuard extends AbstractMfaStateGuard {

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();
        int currentRetryCount = factorContext.getRetryCount();
        int maxRetries = getMaxRetries();

        String currentFactor = factorContext.getCurrentProcessingFactor() != null ?
                factorContext.getCurrentProcessingFactor().name() : null;
        if (currentFactor != null) {
            Integer factorRetryCount = getFactorRetryCount(factorContext, currentFactor);
            int factorMaxRetries = getFactorMaxRetries(currentFactor);

            if (factorRetryCount >= factorMaxRetries) {
                log.warn("Factor {} retry limit exceeded for session: {}",
                        currentFactor, sessionId);
                return false;
            }
        }

        boolean withinLimit = currentRetryCount < maxRetries;

        if (!withinLimit) {
            log.warn("Total retry limit exceeded for session: {}", sessionId);
        }

        return withinLimit;
    }

    private int getMaxRetries() {
        
        return 3;
    }

    private int getFactorMaxRetries(String factorType) {
        
        return switch (factorType.toUpperCase()) {
            case "MFA_OTT", "SMS" -> 5;
            case "TOTP", "FIDO", "MFA_PASSKEY" -> 3;
            default -> getMaxRetries(); 
        };
    }

    private Integer getFactorRetryCount(FactorContext factorContext, String factorType) {
        String key = "retryCount_" + factorType;
        Object retryCount = factorContext.getAttribute(key);

        if (retryCount instanceof Integer) {
            return (Integer) retryCount;
        }

        return 0;
    }

    public void incrementRetryCount(FactorContext factorContext) {
        
        factorContext.setRetryCount(factorContext.getRetryCount() + 1);

        String currentFactor = factorContext.getCurrentProcessingFactor() != null ?
                factorContext.getCurrentProcessingFactor().name() : null;
        if (currentFactor != null) {
            String key = "retryCount_" + currentFactor;
            Integer currentCount = getFactorRetryCount(factorContext, currentFactor);
            factorContext.setAttribute(key, currentCount + 1);
        }

            }

    public void resetRetryCount(FactorContext factorContext, String factorType) {
        if (factorType != null) {
            String key = "retryCount_" + factorType;
            factorContext.removeAttribute(key);
                    }
    }

    @Override
    public String getFailureReason() {
        return "Maximum retry attempts exceeded";
    }

    public int getRemainingRetries(FactorContext factorContext) {
        int maxRetries = getMaxRetries();
        int currentRetries = factorContext.getRetryCount();
        return Math.max(0, maxRetries - currentRetries);
    }

    public int getFactorRemainingRetries(FactorContext factorContext, String factorType) {
        int maxRetries = getFactorMaxRetries(factorType);
        int currentRetries = getFactorRetryCount(factorContext, factorType);
        return Math.max(0, maxRetries - currentRetries);
    }

    @Override
    public String getGuardName() {
        return "RetryLimitGuard";
    }
}
