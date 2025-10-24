package io.contexa.contexaidentity.security.statemachine.integration;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * State Machine과 Filter 통합 구현체
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class StateMachineFilterIntegrationImpl implements StateMachineFilterIntegration {

    private final MfaStateMachineService stateMachineService;

    @Override
    public boolean preProcess(HttpServletRequest request, HttpServletResponse response,
                              FactorContext context) {
        if (context == null) {
            log.warn("FactorContext is null, cannot pre-process");
            return false;
        }

        String sessionId = context.getMfaSessionId();
        log.debug("Pre-processing for session: {}", sessionId);

        // 현재 상태 확인
        MfaState currentState = stateMachineService.getCurrentState(sessionId);

        // 상태 머신이 초기화되지 않은 경우
        if (currentState == MfaState.NONE) {
            log.info("Initializing state machine for session: {}", sessionId);
            stateMachineService.initializeStateMachine(context, request);
        }

        // FactorContext와 상태 머신 상태 동기화
        if (context.getCurrentState() != currentState) {
            log.debug("Syncing FactorContext state from {} to {}",
                    context.getCurrentState(), currentState);
            context.changeState(currentState);
        }

        // 진행 가능 여부 반환
        return canProceed(request, context);
    }

    @Override
    public void postProcess(HttpServletRequest request, HttpServletResponse response,
                            FactorContext context, Object result) {
        if (context == null) {
            log.warn("FactorContext is null, cannot post-process");
            return;
        }

        String sessionId = context.getMfaSessionId();
        log.debug("Post-processing for session: {} with result: {}",
                sessionId, result != null ? result.getClass().getSimpleName() : "null");

        // 결과에 따른 이벤트 결정
        MfaEvent event = determineEventFromResult(request, result);

        if (event != null) {
            log.info("Sending event {} for session: {}", event, sessionId);
            boolean accepted = stateMachineService.sendEvent(event, context, request);

            if (!accepted) {
                log.warn("Event {} was not accepted for session: {} in current state: {}",
                        event, sessionId, context.getCurrentState());
            }
        }
    }

    @Override
    public boolean canProceed(HttpServletRequest request, FactorContext context) {
        if (context == null) {
            return false;
        }

        MfaState currentState = context.getCurrentState();

        // 터미널 상태인 경우 진행하지 않음
        if (currentState.isTerminal()) {
            log.debug("Current state {} is terminal, should not proceed", currentState);
            return false;
        }

        // 진행 가능한 상태인지 확인
        boolean canProceed = !isBlockingState(currentState);
        log.debug("Session {} in state {} can proceed: {}",
                context.getMfaSessionId(), currentState, canProceed);

        return canProceed;
    }

    /**
     * HTTP 요청과 결과로부터 이벤트 결정
     */
    private MfaEvent determineEventFromResult(HttpServletRequest request, Object result) {
        String requestUri = request.getRequestURI();
        String method = request.getMethod();

        // 팩터 선택
        if (requestUri.contains("/mfa/select-factor") && "POST".equals(method)) {
            String selectedFactor = request.getParameter("factor");
            if (selectedFactor != null) {
                return MfaEvent.FACTOR_SELECTED;
            }
        }

        // 챌린지 요청
        if (requestUri.contains("/mfa/challenge") && "POST".equals(method)) {
            return MfaEvent.INITIATE_CHALLENGE;
        }

        // 검증 시도
        if (requestUri.contains("/mfa/verify") && "POST".equals(method)) {
            return MfaEvent.SUBMIT_FACTOR_CREDENTIAL;
        }

        // 취소
        if (requestUri.contains("/mfa/cancel")) {
            return MfaEvent.USER_ABORTED_MFA;
        }

        // 결과 객체 기반 판단
        if (result != null) {
            String resultType = result.getClass().getSimpleName();

            if (resultType.contains("Success")) {
                return MfaEvent.FACTOR_VERIFIED_SUCCESS;
            } else if (resultType.contains("Failure")) {
                return MfaEvent.FACTOR_VERIFICATION_FAILED;
            }
        }

        return null;
    }

    /**
     * 진행을 막는 상태인지 확인
     */
    private boolean isBlockingState(MfaState state) {
        return state == MfaState.MFA_SESSION_EXPIRED ||
                state == MfaState.MFA_RETRY_LIMIT_EXCEEDED ||
                state == MfaState.MFA_SYSTEM_ERROR;
    }
}