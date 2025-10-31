package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.CompletionDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
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
 * 3. 결정 내용에 따라 Context 수정 및 이벤트 전송
 * 4. 에러 발생 시 SYSTEM_ERROR 상태로 전이
 * </p>
 *
 * @since Phase 2
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CheckCompletionAction extends AbstractMfaStateAction {

    private final MfaPolicyProvider policyProvider;
    private final ApplicationContext applicationContext;

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
            // ALL_REQUIRED_FACTORS_COMPLETED 이벤트로 상태 전이
            context.getStateMachine().sendEvent(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED);

        } else if (decision.isNeedsFactorSelection()) {
            // 다음 팩터가 이미 자동 결정되었는지 확인
            if (factorContext.getCurrentProcessingFactor() != null) {
                // 자동 선택된 경우 - FACTOR_SELECTED 이벤트 전송
                log.info("Next factor already determined: {} for session: {}",
                         factorContext.getCurrentProcessingFactor(), sessionId);
                context.getStateMachine().sendEvent(MfaEvent.FACTOR_SELECTED);
            } else {
                // 수동 선택 필요
                log.info("Manual factor selection needed (attempt: {}) for session: {}",
                         decision.getAttemptCount(), sessionId);
                factorContext.setAttribute("selectFactorAttemptCount",
                                          decision.getAttemptCount());
                context.getStateMachine().sendEvent(MfaEvent.MFA_REQUIRED_SELECT_FACTOR);
            }
        }
    }

    /**
     * MFA FlowConfig 조회
     */
    private AuthenticationFlowConfig findMfaFlowConfig(FactorContext ctx) {
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig == null || platformConfig.getFlows() == null) {
                return null;
            }

            return platformConfig.getFlows().stream()
                .filter(f -> AuthType.MFA.name().equalsIgnoreCase(f.getTypeName()))
                .findFirst()
                .orElse(null);
        } catch (Exception e) {
            log.error("Error loading MFA flow config", e);
            return null;
        }
    }
}
