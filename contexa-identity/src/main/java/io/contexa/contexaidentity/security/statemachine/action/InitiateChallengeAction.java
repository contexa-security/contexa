package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * MFA 챌린지 시작 액션
 */
@Slf4j
@Component
public class InitiateChallengeAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {

        String sessionId = factorContext.getMfaSessionId();
        String factorType = factorContext.getCurrentProcessingFactor() != null ?
                factorContext.getCurrentProcessingFactor().name() : "UNKNOWN";

        log.info("Initiating challenge for factor: {} in session: {}", factorType, sessionId);

        // 챌린지 시작 시간 기록
        factorContext.setAttribute("challengeInitiatedAt", System.currentTimeMillis());

        // 팩터별 챌린지 처리
        switch (factorType) {
            case "OTT":
                log.info("Initiating OTT challenge for session: {}", sessionId);
                factorContext.setAttribute("ottCodeSent", true);
                break;

            case "PASSKEY":
                log.info("Initiating Passkey challenge for session: {}", sessionId);
                factorContext.setAttribute("passkeyOptionsGenerated", true);
                break;

            default:
                log.warn("Unknown factor type for challenge: {}", factorType);
                throw new UnsupportedOperationException("Unsupported factor type: " + factorType);
        }
        context.getExtendedState().getVariables().put("challengeInitiationSuccess", true);
        log.info("Challenge initiated successfully for factor: {} in session: {}",
                factorType, sessionId);
    }
}