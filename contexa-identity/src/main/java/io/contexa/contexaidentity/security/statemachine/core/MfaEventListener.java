package io.contexa.contexaidentity.security.statemachine.core;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;

/**
 * MFA 이벤트 리스너
 */
@FunctionalInterface
public interface MfaEventListener {
    void onEvent(MfaEvent event, FactorContext context, String sessionId);
}
