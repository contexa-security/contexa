package io.contexa.contexaidentity.security.filter.handler;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

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
@Component
@RequiredArgsConstructor
public class MfaStateMachineIntegrator {

    private final MfaStateMachineService stateMachineService;
    private final MfaSessionRepository sessionRepository;
    private final AuthContextProperties properties;

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
     */
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request, java.util.Map<String, Object> additionalHeaders) {
        String sessionId = context.getMfaSessionId();
        log.debug("Sending event {} to unified State Machine for session: {}", event, sessionId);

        try {
            sessionRepository.refreshSession(sessionId);

            if (!isValidEventForCurrentState(event, context.getCurrentState())) {
                log.warn("Event {} is not valid for current state {} in session: {}",
                        event, context.getCurrentState(), sessionId);
                return false;
            }

            boolean accepted = stateMachineService.sendEvent(event, context, request, additionalHeaders);

            if (accepted) {
                log.debug("Event {} accepted by unified State Machine for session: {}", event, sessionId);
            } else {
                // 개선: 구체적인 거부 사유 분석
                String rejectionReason = analyzeEventRejectionReason(context, event);
                log.warn("Event {} rejected by unified State Machine for session: {} - Reason: {}",
                        event, sessionId, rejectionReason);
            }

            return accepted;
        } catch (Exception e) {
            log.error("Failed to send event {} to unified State Machine for session: {}", event, sessionId, e);
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
     * FactorContext 로드 (읽기 전용 스냅샷)
     *
     * <p>
     * Phase 1 완료: Single Source of Truth 패턴 적용
     * State Machine Extended State에서 읽기 전용 스냅샷을 반환합니다.
     * </p>
     *
     * <p>
     * <strong>중요:</strong> 반환된 FactorContext는 읽기 전용입니다.
     * 상태 변경 시도 시 IllegalStateException이 발생합니다.
     * 모든 상태 변경은 State Machine을 통해서만 수행되어야 합니다.
     * </p>
     *
     * @param sessionId MFA 세션 ID
     * @return 읽기 전용 FactorContext 스냅샷 (세션이 없으면 null)
     */
    public FactorContext loadFactorContext(String sessionId) {
        try {
            FactorContext original = stateMachineService.getFactorContext(sessionId);
            if (original == null) {
                return null;
            }
            // Phase 1: 읽기 전용 스냅샷 반환으로 Single Source of Truth 패턴 완성
            return FactorContext.readOnlySnapshot(original);
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
     * 개선: 이벤트 유효성 검증
     */
    private boolean isValidEventForCurrentState(MfaEvent event, MfaState currentState) {
        // 기본적인 이벤트-상태 유효성 검증 로직
        switch (event) {
            case MFA_NOT_REQUIRED:
                return currentState == MfaState.PRIMARY_AUTHENTICATION_COMPLETED;
            case MFA_REQUIRED_SELECT_FACTOR:
                return currentState == MfaState.PRIMARY_AUTHENTICATION_COMPLETED;
            case FACTOR_SELECTED:
                return currentState == MfaState.AWAITING_FACTOR_SELECTION;
            case INITIATE_CHALLENGE:
                return currentState == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION;
            case SUBMIT_FACTOR_CREDENTIAL:
                return currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION;
            case FACTOR_VERIFIED_SUCCESS:
                return currentState == MfaState.FACTOR_VERIFICATION_PENDING ||
                        currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION;
            case FACTOR_VERIFICATION_FAILED:
                return currentState == MfaState.FACTOR_VERIFICATION_PENDING ||
                        currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION;
            default:
                return true; // 기타 이벤트는 기본적으로 허용
        }
    }

    /**
     * 개선: 이벤트 거부 사유 분석
     */
    private String analyzeEventRejectionReason(FactorContext context, MfaEvent event) {
        MfaState currentState = context.getCurrentState();

        if (currentState.isTerminal()) {
            return String.format("State %s is terminal - no further events allowed", currentState);
        }

        switch (currentState) {
            case MFA_SESSION_EXPIRED:
                return "MFA session has expired";
            case MFA_RETRY_LIMIT_EXCEEDED:
            case MFA_FAILED_TERMINAL:
                return "MFA has failed and reached terminal state";
            case NONE:
                return "State Machine not properly initialized";
            default:
                return String.format("Event %s not valid for current state %s", event, currentState);
        }
    }

    /**
     * 시스템 속성인지 확인
     */
    private boolean isSystemAttribute(String key) {
        return key.startsWith("_") ||
                "currentState".equals(key) ||
                "version".equals(key) ||
                "lastUpdated".equals(key) ||
                "stateHash".equals(key) ||
                "storageType".equals(key) ||
                "mfaSessionId".equals(key);
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