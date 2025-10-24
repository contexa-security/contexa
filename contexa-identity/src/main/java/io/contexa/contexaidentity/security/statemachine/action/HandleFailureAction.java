package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * MFA 실패 처리 액션
 */
@Slf4j
@Component
public class HandleFailureAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        log.info("Handling MFA failure for session: {}", sessionId);

        String failureReason = (String) context.getMessageHeader("failureReason");
        if (failureReason == null) {
            failureReason = (String) context.getExtendedState().getVariables().get("lastError");
        }

        factorContext.setLastError(failureReason != null ? failureReason : "Unknown error");
        factorContext.setAttribute("lastFailureTime", System.currentTimeMillis());

        int retryCount = factorContext.getRetryCount();
        factorContext.setRetryCount(retryCount + 1);

        Integer maxRetries = (Integer) context.getExtendedState().getVariables().get("maxRetries");
        if (maxRetries == null) {
            maxRetries = 3;
        }

        if (factorContext.getRetryCount() >= maxRetries) {
            log.warn("Max retry attempts exceeded for session: {}", sessionId);

            // ExtendedState에 재시도 초과 플래그 설정
            context.getExtendedState().getVariables().put("retryLimitExceeded", true);
            context.getExtendedState().getVariables().put("exceedTime", System.currentTimeMillis());

            // 현재 처리 중인 팩터 정보 저장
            if (factorContext.getCurrentProcessingFactor() != null) {
                context.getExtendedState().getVariables().put("failedFactor",
                        factorContext.getCurrentProcessingFactor().name());
            }
        } else {
            log.info("Retry attempt {} of {} for session: {}",
                    factorContext.getRetryCount(), maxRetries, sessionId);

            // 재시도 가능 상태 설정
            context.getExtendedState().getVariables().put("retryAllowed", true);
        }
    }
}