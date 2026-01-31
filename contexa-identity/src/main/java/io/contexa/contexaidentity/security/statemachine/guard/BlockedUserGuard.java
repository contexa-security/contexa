package io.contexa.contexaidentity.security.statemachine.guard;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class BlockedUserGuard extends AbstractMfaStateGuard {

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();
        String username = factorContext.getUsername();

        Object blockedObj = factorContext.getAttribute(FactorContextAttributes.StateControl.BLOCKED);
        boolean isBlocked = Boolean.TRUE.equals(blockedObj);

        if (isBlocked) {
            String blockReason = (String) factorContext.getAttribute(FactorContextAttributes.MessageAndReason.BLOCK_REASON);
            log.warn("[BlockedUserGuard] User {} is blocked for session: {}, reason: {}",
                    username, sessionId, blockReason != null ? blockReason : "UNKNOWN");
            return false;
        }

        return true;
    }

    @Override
    public String getFailureReason() {
        return "User is blocked from MFA process";
    }

    @Override
    public String getGuardName() {
        return "BlockedUserGuard";
    }

}
