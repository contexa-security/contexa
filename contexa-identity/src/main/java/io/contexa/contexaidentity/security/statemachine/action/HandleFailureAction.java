package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class HandleFailureAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();

        String failureReason = (String) context.getMessageHeader("failureReason");
        if (failureReason == null) {
            failureReason = (String) context.getExtendedState().getVariables().get("lastError");
        }

        factorContext.setLastError(failureReason != null ? failureReason : "Unknown error");

        int retryCount = factorContext.getRetryCount();
        factorContext.setRetryCount(retryCount + 1);

        Integer maxRetries = (Integer) context.getExtendedState().getVariables().get("maxRetries");
        if (maxRetries == null) {
            maxRetries = 3;
        }

        if (factorContext.getRetryCount() >= maxRetries) {
            log.warn("Max retry attempts exceeded for session: {}", sessionId);
        } else {
        }
    }
}