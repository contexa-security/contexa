package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.NextFactorDecision;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * Phase 2: 다음 팩터 결정 Action
 *
 * <p>
 * PolicyProvider로부터 결정을 받아 State Machine에서 Context를 수정합니다.
 * Single Source of Truth 패턴 구현의 핵심 클래스.
 * </p>
 *
 * <p>
 * 실행 흐름:
 * 1. PolicyProvider.evaluateNextFactor()로 결정 획득 (읽기 전용)
 * 2. 결정 내용에 따라 Context 수정 (State Machine에서만)
 * 3. 에러 발생 시 SYSTEM_ERROR 상태로 전이
 * </p>
 *
 * @since Phase 2
 */
@Slf4j
@Component
public class DetermineNextFactorAction extends AbstractMfaStateAction {

    private final MfaPolicyProvider policyProvider;

    public DetermineNextFactorAction(MfaPolicyProvider policyProvider) {
        this.policyProvider = policyProvider;
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                            FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();
        log.debug("Determining next factor for session: {}", sessionId);

        NextFactorDecision decision = policyProvider.evaluateNextFactor(factorContext);

        if (decision.getErrorMessage() != null) {
            log.error("Error determining next factor: {}", decision.getErrorMessage());
            factorContext.changeState(MfaState.MFA_SYSTEM_ERROR);
            factorContext.setLastError(decision.getErrorMessage());
            return;
        }

        if (decision.isHasNextFactor()) {
            // 다음 팩터가 자동 결정됨
            factorContext.setCurrentProcessingFactor(decision.getNextFactorType());
            factorContext.setCurrentStepId(decision.getNextStepId());

            // Phase 2.3: SelectFactorAction의 팩터별 속성 설정 로직 복제
            setFactorSpecificAttributes(factorContext, decision.getNextFactorType());

            // Phase 4: 이벤트 추천 변경 - FACTOR_SELECTED → INITIATE_CHALLENGE_AUTO
            factorContext.setAttribute(FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION, MfaEvent.INITIATE_CHALLENGE_AUTO);

            log.info("Next factor auto-selected: {} (StepId: {}) for session: {}",
                     decision.getNextFactorType(), decision.getNextStepId(), sessionId);
        } else if (decision.isAllFactorsCompleted()) {
            // 모든 필수 팩터 완료
            // Phase 4: 이벤트 추천
            factorContext.setAttribute(FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION,
                                       MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED);

            log.info("All required factors completed for session: {}", sessionId);
        } else {
            // 수동 선택 필요 (다음 팩터가 자동 결정되지 않음)
            // Phase 4: 이벤트 추천
            factorContext.setAttribute(FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION,
                                       MfaEvent.MFA_REQUIRED_SELECT_FACTOR);

            log.info("Manual factor selection required for session: {}", sessionId);
        }
    }

    /**
     * Phase 2.3: SelectFactorAction의 팩터별 속성 설정 로직 복제
     * 다음 팩터 자동 선택 시 SelectFactorAction을 건너뛰므로 여기서 속성 설정
     */
    private void setFactorSpecificAttributes(FactorContext factorContext, AuthType factorType) {
        String sessionId = factorContext.getMfaSessionId();

        switch (factorType) {
            case OTT:
                // OTT 전송 방법 설정
                String ottMethod = (String) factorContext.getAttribute(
                    FactorContextAttributes.UserInfo.USER_OTT_PREFERENCE);
                if (ottMethod == null) {
                    ottMethod = "EMAIL";
                }
                factorContext.setAttribute(
                    FactorContextAttributes.FactorInfo.OTT_DELIVERY_METHOD,
                    ottMethod);
                log.debug("OTT delivery method set to: {} for session: {}", ottMethod, sessionId);
                break;

            case PASSKEY:
                // Passkey 타입 설정
                String userAgent = (String) factorContext.getAttribute(
                    FactorContextAttributes.DeviceAndSession.USER_AGENT);
                String passkeyType = "PLATFORM";
                if (userAgent != null && userAgent.contains("Mobile")) {
                    passkeyType = "MOBILE";
                }
                factorContext.setAttribute(
                    FactorContextAttributes.FactorInfo.PASSKEY_TYPE,
                    passkeyType);
                log.debug("Passkey type set to: {} for session: {}", passkeyType, sessionId);
                break;

            default:
                log.debug("No additional settings for factor: {}", factorType);
        }

        // 팩터 선택 시간 기록
        factorContext.setAttribute(
            FactorContextAttributes.Timestamps.FACTOR_SELECTED_AT,
            System.currentTimeMillis());
    }
}
