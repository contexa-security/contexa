package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.exception.MfaStateMachineExceptions;
import io.contexa.contexaidentity.security.statemachine.exception.MfaStateMachineExceptions.ChallengeGenerationException;
import io.contexa.contexaidentity.security.statemachine.exception.MfaStateMachineExceptions.FactorVerificationException;
import io.contexa.contexaidentity.security.statemachine.exception.MfaStateMachineExceptions.InvalidFactorException;
import io.contexa.contexaidentity.security.statemachine.exception.MfaStateMachineExceptions.StateTransitionException;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.statemachine.StateContext;
import org.springframework.statemachine.action.Action;

@Slf4j
@RequiredArgsConstructor
public abstract class AbstractMfaStateAction implements Action<MfaState, MfaEvent>, ApplicationContextAware {

    protected ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public final void execute(StateContext<MfaState, MfaEvent> context) {
        String sessionId = extractSessionId(context);
        log.debug("Executing action {} for session: {}", this.getClass().getSimpleName(), sessionId);

        FactorContext factorContext = null;
        try {
            // FactorContext 추출
            factorContext = extractFactorContext(context);
            if (factorContext == null) {
                throw new IllegalStateException("FactorContext not found in state machine context");
            }

            // 전제조건 검증
            validatePreconditions(context, factorContext);

            // 액션별 구체적인 로직 실행
            doExecute(context, factorContext);

            // 변경된 FactorContext를 다시 상태 머신에 반영
            updateStateMachineVariables(context, factorContext);

            log.debug("Action {} completed successfully for session: {}",
                    this.getClass().getSimpleName(), sessionId);

        } catch (InvalidFactorException | ChallengeGenerationException |
                 FactorVerificationException | StateTransitionException e) {
            log.error("Business exception in action {} for session: {}: {}",
                    this.getClass().getSimpleName(), sessionId, e.getMessage());

            // 1. 에러 정보를 컨텍스트에 저장 (Single Source of Truth: FactorContext만 사용)
            assert factorContext != null;
            factorContext.setLastError(e.getMessage());

            // 3. 에러 이벤트 전송
            handleBusinessException(context, factorContext, e);

            // 4. 중요: 예외를 다시 발생시켜 상위로 전파
            throw new MfaStateMachineExceptions.StateMachineActionException(
                    "MFA action failed: " + e.getMessage(), e);

        } catch (Exception e) {
            // 기타 예외도 동일하게 처리
            log.error("Unexpected exception in action", e);

            if (factorContext != null) {
                // Phase 2 개선: handleUnexpectedError() 호출하여 errorEventRecommendation 설정
                handleUnexpectedError(context, factorContext, e);
            }

            // 예외 재발생
            throw new MfaStateMachineExceptions.StateMachineActionException(
                    "Unexpected error in MFA action", e);
        }
    }

    /**
     * 전제조건 검증
     */
    protected void validatePreconditions(StateContext<MfaState, MfaEvent> context,
                                         FactorContext factorContext) throws Exception {
        // 기본 구현은 아무것도 하지 않음
        // 하위 클래스에서 필요시 오버라이드
    }

    /**
     * 각 액션의 구체적인 비즈니스 로직을 구현
     */
    protected abstract void doExecute(StateContext<MfaState, MfaEvent> context,
                                      FactorContext factorContext) throws Exception;

    /**
     * 비즈니스 예외 처리
     * Phase 2 개선: 이벤트 추천만 하고 직접 전송하지 않음
     */
    protected void handleBusinessException(StateContext<MfaState, MfaEvent> context,
                                           FactorContext factorContext,
                                           RuntimeException e) {
        // 에러 정보 저장 (Single Source of Truth: FactorContext만 사용)
        if (factorContext != null) {
            factorContext.setLastError(e.getMessage());

            // Phase 2 개선: 이벤트 추천 저장 (Handler가 처리)
            if (e instanceof InvalidFactorException) {
                factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                                         MfaEvent.SYSTEM_ERROR);

            } else if (e instanceof ChallengeGenerationException) {
                factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                                         MfaEvent.CHALLENGE_INITIATION_FAILED);

            } else if (e instanceof FactorVerificationException) {
                factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                                         MfaEvent.FACTOR_VERIFICATION_FAILED);
            }
        }
    }

    /**
     * 세션 만료 상태로 전이
     * Phase 2 개선: 이벤트 추천만 하고 직접 전송/상태변경 하지 않음
     */
    protected void transitionToExpiredState(StateContext<MfaState, MfaEvent> context,
                                            FactorContext factorContext) {
        if (factorContext != null) {
            // Phase 2 개선: 직접 state 변경 대신 이벤트 추천
            factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                                     MfaEvent.SESSION_TIMEOUT);
            factorContext.setLastError("Session timeout");
        }
    }

    /**
     * 예상치 못한 에러 처리
     * P2-2 수정: 직접 상태 변경 대신 이벤트 추천 (Single Source of Truth 패턴 준수)
     */
    protected void handleUnexpectedError(StateContext<MfaState, MfaEvent> context,
                                         FactorContext factorContext,
                                         Exception e) {
        if (factorContext != null) {
            factorContext.setLastError("Unexpected error: " + e.getMessage());
            // P2-2 수정: 직접 changeState() 호출 대신 이벤트 추천 설정
            // Handler가 이 추천을 읽어서 SYSTEM_ERROR 이벤트를 State Machine에 전송
            factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION,
                                     MfaEvent.SYSTEM_ERROR);
        }

        // TODO: Dead Letter Queue 구현 시 unexpectedError 이벤트 발행 추가
        // 현재는 FactorContext.lastError 및 ERROR_EVENT_RECOMMENDATION에 저장되어 있음
    }

    /**
     * StateContext 에서 세션 ID 추출
     */
    protected String extractSessionId(StateContext<MfaState, MfaEvent> context) {
        String sessionId = StateContextHelper.getFactorContext(context).getMfaSessionId();
        if (sessionId == null) {
            sessionId = (String) context.getMessageHeader("mfaSessionId");
        }
        if (sessionId == null) {
            sessionId = (String) context.getExtendedState().getVariables().get("sessionId");
        }
        return sessionId;
    }

    /**
     * StateContext 에서 FactorContext 추출
     */
    protected FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        return StateContextHelper.getFactorContext(context);
    }

    /**
     * 변경된 FactorContext를 StateContext에 업데이트
     */
    protected void updateStateMachineVariables(StateContext<MfaState, MfaEvent> context,
                                               FactorContext factorContext) {
        StateContextHelper.setFactorContext(context, factorContext);
    }

    /**
     * P1-1: MFA FlowConfig 조회 (공통 메서드)
     * Phase 2 개선: 코드 중복 제거
     */
    protected AuthenticationFlowConfig findMfaFlowConfig(FactorContext ctx) {
        try {
            if (applicationContext == null) {
                log.error("ApplicationContext is not set for action: {}", this.getClass().getSimpleName());
                return null;
            }

            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);

            return platformConfig.getFlows().stream()
                .filter(f -> AuthType.MFA.name().equalsIgnoreCase(f.getTypeName()))
                .findFirst()
                .orElse(null);
        } catch (Exception e) {
            log.error("Error loading MFA flow config for session: {}",
                     ctx != null ? ctx.getMfaSessionId() : "unknown", e);
            return null;
        }
    }
}