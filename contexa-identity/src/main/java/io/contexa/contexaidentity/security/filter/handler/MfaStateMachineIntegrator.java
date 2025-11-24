package io.contexa.contexaidentity.security.filter.handler;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

/**
 * Repository 패턴 기반 완전 일원화된 MfaStateMachineIntegrator
 *
 * <p>
 * Single Source of Truth 패턴: State Machine Extended State가 유일한 상태 저장소입니다.
 * FactorContext는 읽기 전용 스냅샷으로만 제공되며, 모든 상태 변경은 State Machine을 통해서만 수행됩니다.
 * </p>
 *
 * 개선사항:
 * - 이벤트 처리 표준화: 일관된 처리 패턴 적용
 * - 읽기 전용 스냅샷: 불변 FactorContext 제공으로 안전성 향상
 */
@Slf4j
public class MfaStateMachineIntegrator {

    private final MfaStateMachineService stateMachineService;
    private final MfaSessionRepository sessionRepository;
    private final AuthContextProperties properties;

    public MfaStateMachineIntegrator(
            MfaStateMachineService stateMachineService,
            MfaSessionRepository sessionRepository,
            AuthContextProperties properties) {
        this.stateMachineService = stateMachineService;
        this.sessionRepository = sessionRepository;
        this.properties = properties;
    }

    @PostConstruct
    public void initialize() {
        sessionRepository.setSessionTimeout(properties.getMfa().getSessionTimeout());
        log.info("MfaStateMachineIntegrator initialized with {} repository - Single Source of Truth pattern",
                sessionRepository.getRepositoryType());
    }

    /**
     * State Machine 초기화 - Response 포함 버전 (Redis 쿠키 설정 지원)
     */
    public void initializeStateMachine(FactorContext context, HttpServletRequest request, HttpServletResponse response) {
        String sessionId = context.getMfaSessionId();

        log.info("Initializing unified State Machine for session: {} using {} repository",
                sessionId, sessionRepository.getRepositoryType());

        try {
            // State Machine 초기화 (FactorContext도 함께 저장됨)
            stateMachineService.initializeStateMachine(context, request);

            // Repository를 통한 세션 저장
            sessionRepository.storeSession(sessionId, request, response);

            log.info("Unified State Machine initialized successfully for session: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to initialize unified State Machine for session: {}", sessionId, e);
            throw new StateMachineIntegrationException("State Machine initialization failed", e);
        }
    }

    /**
     * 완전 일원화: 이벤트 전송
     */
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        return sendEvent(event, context, request, null);
    }

    /**
     * Phase 2: 추가 헤더와 함께 이벤트 전송
     * Phase 5: 사전 검증 제거 - State Machine에 완전 위임
     */
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request, Map<String, Object> additionalHeaders) {
        String sessionId = context.getMfaSessionId();
        log.debug("Sending event {} to State Machine for session: {}", event, sessionId);

        try {
            sessionRepository.refreshSession(sessionId);

            // Phase 5: State Machine에 직접 위임 (사전 검증 제거)
            boolean accepted = stateMachineService.sendEvent(event, context, request, additionalHeaders);

            if (accepted) {
                log.debug("Event {} accepted by State Machine for session: {}", event, sessionId);
            } else {
                String rejectionReason = analyzeEventRejectionReason(context, event);
                log.warn("Event {} rejected by State Machine for session: {} - Reason: {}",
                        event, sessionId, rejectionReason);
            }

            return accepted;
        } catch (Exception e) {
            log.error("Failed to send event {} to State Machine for session: {}", event, sessionId, e);
            return false;
        }
    }

    /**
     * 완전 일원화: 현재 상태 조회
     */
    public MfaState getCurrentState(String sessionId) {
        try {
            return stateMachineService.getCurrentState(sessionId);
        } catch (Exception e) {
            log.error("Failed to get current state from unified State Machine for session: {}", sessionId, e);
            return MfaState.NONE;
        }
    }

    /**
     * FactorContext 로드
     *
     * <p>
     * State Machine에서 관리하는 FactorContext를 반환합니다.
     * sendEvent()에서 Context를 수정해야 하므로 원본을 그대로 반환합니다.
     * </p>
     *
     * @param sessionId MFA 세션 ID
     * @return FactorContext (세션이 없으면 null)
     */
    public FactorContext loadFactorContext(String sessionId) {
        try {
            FactorContext original = stateMachineService.getFactorContext(sessionId);
            if (original == null) {
                return null;
            }
            // sendEvent()에서 Context를 수정해야 하므로 원본을 그대로 반환
            return original;
        } catch (Exception e) {
            log.error("Failed to load FactorContext from unified State Machine for session: {}", sessionId, e);
            return null;
        }
    }

    public void saveFactorContext(FactorContext context) {
        try {
            stateMachineService.saveFactorContext(context);

            log.debug("FactorContext saved to unified State Machine: session={}, state={}, version={}",
                    context.getMfaSessionId(), context.getCurrentState(), context.getVersion());
        } catch (Exception e) {
            log.error("Failed to save FactorContext to unified State Machine for session: {}",
                    context.getMfaSessionId(), e);
        }
    }

    public void releaseStateMachine(String sessionId) {
        log.info("Releasing unified State Machine for session: {}", sessionId);

        try {
            stateMachineService.releaseStateMachine(sessionId);

            log.info("Unified State Machine released successfully for session: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to release unified State Machine for session: {}", sessionId, e);
        }
    }

    public FactorContext loadFactorContextFromRequest(HttpServletRequest request) {
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId == null) {
            log.trace("No MFA session ID found in {}. Cannot load FactorContext.",
                    sessionRepository.getRepositoryType());
            return null;
        }

        if (!sessionRepository.existsSession(mfaSessionId)) {
            log.trace("MFA session {} not found in {}. Cannot load FactorContext.",
                    mfaSessionId, sessionRepository.getRepositoryType());
            return null;
        }

        return loadFactorContext(mfaSessionId);
    }

    public MfaState getCurrentStateFromRequest(HttpServletRequest request) {
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId == null) {
            return MfaState.NONE;
        }

        if (!sessionRepository.existsSession(mfaSessionId)) {
            return MfaState.NONE;
        }

        return getCurrentState(mfaSessionId);
    }

    public boolean isValidMfaSession(HttpServletRequest request) {
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId == null) {
            return false;
        }

        if (!sessionRepository.existsSession(mfaSessionId)) {
            return false;
        }

        FactorContext context = loadFactorContext(mfaSessionId);
        return context != null && !context.getCurrentState().isTerminal();
    }

    public void cleanupSession(HttpServletRequest request) {
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId != null) {
            releaseStateMachine(mfaSessionId);
            sessionRepository.removeSession(mfaSessionId, request, null);

            log.debug("Session cleanup completed for MFA session: {} using {} repository",
                    mfaSessionId, sessionRepository.getRepositoryType());
        }
    }

    public void cleanupSession(HttpServletRequest request, HttpServletResponse response) {
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId != null) {
            releaseStateMachine(mfaSessionId);
            sessionRepository.removeSession(mfaSessionId, request, response);

            log.debug("Session cleanup with response completed for MFA session: {} using {} repository",
                    mfaSessionId, sessionRepository.getRepositoryType());
        }
    }

    public boolean updateStateOnly(String sessionId, MfaState newState) {
        try {
            return stateMachineService.updateStateOnly(sessionId, newState);
        } catch (Exception e) {
            log.error("Failed to update state only for session: {}", sessionId, e);
            return false;
        }
    }

    public String getSessionRepositoryInfo() {
        return String.format("Repository: %s, Timeout: %s",
                sessionRepository.getRepositoryType(),
                properties.getMfa().getSessionTimeout());
    }

    /**
     * Phase 6: 이벤트 거부 사유 상세 분석
     * State Machine이 이벤트를 거부했을 때 다음 정보를 제공:
     * 1. 거부 사유
     * 2. 해당 이벤트가 가능한 소스 상태들
     * 3. 현재 상태에서 가능한 이벤트들
     * 4. nextEventRecommendation (있는 경우)
     */
    private String analyzeEventRejectionReason(FactorContext context, MfaEvent event) {
        MfaState currentState = context.getCurrentState();

        // Terminal state 체크
        if (currentState.isTerminal()) {
            return String.format("State [%s] is terminal - no further events allowed", currentState);
        }

        // 특수 상태별 메시지
        if (currentState == MfaState.MFA_SESSION_EXPIRED) {
            return "MFA session has expired";
        }
        if (currentState == MfaState.MFA_RETRY_LIMIT_EXCEEDED || currentState == MfaState.MFA_FAILED_TERMINAL) {
            return "MFA has failed and reached terminal state";
        }
        if (currentState == MfaState.NONE) {
            return "State Machine not properly initialized";
        }

        // Phase 6: 상세 거부 사유 생성
        StringBuilder reason = new StringBuilder();
        reason.append(String.format("Event [%s] not valid for current state [%s]. ", event, currentState));

        // 해당 이벤트가 가능한 소스 상태들 표시
        String validSourceStates = getValidSourceStatesForEvent(event);
        if (validSourceStates != null && !validSourceStates.isEmpty()) {
            reason.append(String.format("Valid source states for %s: [%s]. ", event, validSourceStates));
        }

        // 현재 상태에서 가능한 이벤트들 표시
        String validEvents = getValidEventsForState(currentState);
        if (validEvents != null && !validEvents.isEmpty()) {
            reason.append(String.format("Valid events for %s: [%s]. ", currentState, validEvents));
        }

        // nextEventRecommendation 확인
        Object recommended = context.getAttribute(io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION);
        if (recommended != null) {
            reason.append(String.format("Recommended event: [%s]. ", recommended));
        } else {
            reason.append("No event recommendation available. ");
        }

        return reason.toString();
    }

    /**
     * Phase 6: 이벤트별 유효한 소스 상태 반환
     * State Machine Configuration 기반 매핑
     */
    private String getValidSourceStatesForEvent(MfaEvent event) {
        return switch (event) {
            case PRIMARY_AUTH_SUCCESS -> "NONE";
            case MFA_NOT_REQUIRED, MFA_REQUIRED_SELECT_FACTOR, INITIATE_CHALLENGE_AUTO ->
                    "PRIMARY_AUTHENTICATION_COMPLETED";
            case FACTOR_SELECTED ->
                    "AWAITING_FACTOR_SELECTION, FACTOR_VERIFICATION_COMPLETED";
            case INITIATE_CHALLENGE ->
                    "AWAITING_FACTOR_CHALLENGE_INITIATION, FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION";
            case SUBMIT_FACTOR_CREDENTIAL ->
                    "FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION";
            case FACTOR_VERIFIED_SUCCESS, FACTOR_VERIFICATION_FAILED ->
                    "FACTOR_VERIFICATION_PENDING";
            case DETERMINE_NEXT_FACTOR, ALL_REQUIRED_FACTORS_COMPLETED ->
                    "FACTOR_VERIFICATION_COMPLETED";
            case ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN ->
                    "ALL_FACTORS_COMPLETED";
            case SESSION_TIMEOUT, RETRY_LIMIT_EXCEEDED, USER_ABORTED_MFA, SYSTEM_ERROR ->
                    "Multiple non-terminal states (terminal event)";
            default -> "Unknown event";
        };
    }

    /**
     * Phase 6: 상태별 유효한 이벤트 반환
     * State Machine Configuration 기반 매핑
     */
    private String getValidEventsForState(MfaState state) {
        return switch (state) {
            case NONE ->
                    "PRIMARY_AUTH_SUCCESS";
            case PRIMARY_AUTHENTICATION_COMPLETED ->
                    "MFA_NOT_REQUIRED, MFA_REQUIRED_SELECT_FACTOR, INITIATE_CHALLENGE_AUTO, SESSION_TIMEOUT, SYSTEM_ERROR";
            case AWAITING_FACTOR_SELECTION ->
                    "FACTOR_SELECTED, SESSION_TIMEOUT, USER_ABORTED_MFA, SYSTEM_ERROR";
            case AWAITING_FACTOR_CHALLENGE_INITIATION ->
                    "INITIATE_CHALLENGE, SESSION_TIMEOUT, USER_ABORTED_MFA, SYSTEM_ERROR";
            case FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ->
                    "INITIATE_CHALLENGE, SUBMIT_FACTOR_CREDENTIAL, SESSION_TIMEOUT, USER_ABORTED_MFA, SYSTEM_ERROR";
            case FACTOR_VERIFICATION_PENDING ->
                    "FACTOR_VERIFIED_SUCCESS, FACTOR_VERIFICATION_FAILED, SESSION_TIMEOUT, RETRY_LIMIT_EXCEEDED, SYSTEM_ERROR";
            case FACTOR_VERIFICATION_COMPLETED ->
                    "DETERMINE_NEXT_FACTOR, ALL_REQUIRED_FACTORS_COMPLETED, FACTOR_SELECTED, SESSION_TIMEOUT, SYSTEM_ERROR";
            case ALL_FACTORS_COMPLETED ->
                    "ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN, SESSION_TIMEOUT, SYSTEM_ERROR";
            case MFA_SUCCESSFUL, MFA_NOT_REQUIRED, MFA_FAILED_TERMINAL, MFA_SESSION_EXPIRED,
                 MFA_RETRY_LIMIT_EXCEEDED, MFA_CANCELLED, MFA_SYSTEM_ERROR ->
                    "None (terminal state)";
            default ->
                    "Unknown state";
        };
    }

    /**
     * State Machine 통합 예외 클래스
     */
    public static class StateMachineIntegrationException extends RuntimeException {
        public StateMachineIntegrationException(String message) {
            super(message);
        }

        public StateMachineIntegrationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}