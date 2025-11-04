package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.CompletionDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * Phase 2: 완료 여부 확인 Action
 *
 * <p>
 * PolicyProvider로부터 결정을 받아 State Machine에서 Context를 수정합니다.
 * Single Source of Truth 패턴 구현의 핵심 클래스.
 * </p>
 *
 * <p>
 * 실행 흐름:
 * 1. MFA FlowConfig 조회
 * 2. PolicyProvider.evaluateCompletion()으로 결정 획득 (읽기 전용)
 * 3. 결정 내용에 따라 Context 수정 및 이벤트 추천
 * 4. 에러 발생 시 예외 발생 (AbstractMfaStateAction이 처리)
 * </p>
 *
 * @since Phase 2
 * @since P1-1 ApplicationContext는 AbstractMfaStateAction으로부터 상속
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CheckCompletionAction extends AbstractMfaStateAction {

    private final MfaPolicyProvider policyProvider;

    // P1-1: ApplicationContext는 부모 클래스에서 자동 주입됨

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                            FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();
        log.debug("Checking completion for session: {}", sessionId);

        // FlowConfig 조회
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(factorContext);
        if (mfaFlowConfig == null) {
            log.error("MFA flow config not found for session: {}", sessionId);
            factorContext.changeState(MfaState.MFA_SYSTEM_ERROR);
            factorContext.setLastError("MFA flow configuration not found");
            return;
        }

        // PolicyProvider에서 결정만 받아옴 (읽기 전용)
        CompletionDecision decision = policyProvider.evaluateCompletion(
            factorContext, mfaFlowConfig
        );

        if (decision.getErrorMessage() != null) {
            log.error("Completion evaluation error: {}", decision.getErrorMessage());
            factorContext.changeState(MfaState.MFA_SYSTEM_ERROR);
            factorContext.setLastError(decision.getErrorMessage());
            return;
        }

        if (decision.isCompleted()) {
            log.info("All factors completed for session: {}", sessionId);
            // Phase 2 개선: Action은 이벤트를 추천만 하고, Handler가 전송
            factorContext.setAttribute("nextEventRecommendation", MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED);
            factorContext.setAttribute("completionDecision", decision.isCompleted());

        } else if (decision.isNeedsFactorSelection()) {
            // 다음 팩터가 이미 자동 결정되었는지 확인
            if (factorContext.getCurrentProcessingFactor() != null) {
                // 자동 선택된 경우
                log.info("Next factor already determined: {} for session: {}",
                         factorContext.getCurrentProcessingFactor(), sessionId);
                factorContext.setAttribute("nextEventRecommendation", MfaEvent.FACTOR_SELECTED);
            } else {
                // 수동 선택 필요
                log.info("Manual factor selection needed (attempt: {}) for session: {}",
                         decision.getAttemptCount(), sessionId);
                factorContext.setAttribute("selectFactorAttemptCount",
                                          decision.getAttemptCount());
                factorContext.setAttribute("nextEventRecommendation", MfaEvent.MFA_REQUIRED_SELECT_FACTOR);
            }
            factorContext.setAttribute("completionDecision", decision);
        }
    }

    // P1-1: findMfaFlowConfig() 메서드는 AbstractMfaStateAction으로 이동됨
}
