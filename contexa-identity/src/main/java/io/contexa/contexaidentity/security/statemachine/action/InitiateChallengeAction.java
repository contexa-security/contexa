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
                // Phase 2.2: SelectFactorAction에서 설정한 ottDeliveryMethod 활용
                String ottDeliveryMethod = (String) factorContext.getAttribute("ottDeliveryMethod");
                if (ottDeliveryMethod == null) {
                    log.warn("[InitiateChallengeAction] ottDeliveryMethod not set, defaulting to EMAIL for session: {}", sessionId);
                    ottDeliveryMethod = "EMAIL";
                    factorContext.setAttribute("ottDeliveryMethod", ottDeliveryMethod);
                }

                log.info("[InitiateChallengeAction] Initiating OTT challenge via {} for session: {}",
                        ottDeliveryMethod, sessionId);
                break;

            case "PASSKEY":
                // Phase 2.2: SelectFactorAction에서 설정한 passkeyType 활용
                String passkeyType = (String) factorContext.getAttribute("passkeyType");
                if (passkeyType == null) {
                    log.warn("[InitiateChallengeAction] passkeyType not set, defaulting to PLATFORM for session: {}", sessionId);
                    passkeyType = "PLATFORM";
                    factorContext.setAttribute("passkeyType", passkeyType);
                }

                log.info("[InitiateChallengeAction] Initiating Passkey challenge with type {} for session: {}",
                        passkeyType, sessionId);
                break;

            default:
                log.warn("Unknown factor type for challenge: {}", factorType);
                factorContext.setAttribute("errorEventRecommendation", MfaEvent.CHALLENGE_INITIATION_FAILED);
                throw new UnsupportedOperationException("Unsupported factor type: " + factorType);
        }
        context.getExtendedState().getVariables().put("challengeInitiationSuccess", true);
        log.info("Challenge initiated successfully for factor: {} in session: {}",
                factorType, sessionId);
    }
}