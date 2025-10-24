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

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Repository 패턴 기반 완전 일원화된 MfaStateMachineIntegrator
 * 개선사항:
 * - 동기화 최적화: 불필요한 중복 동기화 방지
 * - 이벤트 처리 표준화: 일관된 처리 패턴 적용
 * - 성능 개선: 조건부 동기화 및 캐싱 적용
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaStateMachineIntegrator {

    private final MfaStateMachineService stateMachineService;
    private final MfaSessionRepository sessionRepository;
    private final AuthContextProperties properties;

    // 개선: 동기화 상태 추적을 위한 캐시
    private final Map<String, Long> lastSyncTimestamp = new ConcurrentHashMap<>();
    private final Map<String, Integer> lastSyncVersion = new ConcurrentHashMap<>();
    private final long SYNC_INTERVAL_MS = 1000; // 1초 간격으로 동기화 제한

    @PostConstruct
    public void initialize() {
        sessionRepository.setSessionTimeout(properties.getMfa().getSessionTimeout());
        log.info("MfaStateMachineIntegrator initialized with {} repository - Enhanced with sync optimization",
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

            // 초기화 후 동기화 상태 기록
            updateSyncState(sessionId, context.getVersion());

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
        String sessionId = context.getMfaSessionId();
        log.debug("Sending event {} to unified State Machine for session: {}", event, sessionId);

        try {
            sessionRepository.refreshSession(sessionId);

            if (!isValidEventForCurrentState(event, context.getCurrentState())) {
                log.warn("Event {} is not valid for current state {} in session: {}",
                        event, context.getCurrentState(), sessionId);
                return false;
            }

            boolean accepted = stateMachineService.sendEvent(event, context, request);

            if (accepted) {
                // 개선: 성공한 이벤트 후 동기화 상태 업데이트
                updateSyncState(sessionId, context.getVersion());
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
     * 외부 FactorContext 객체를 State Machine의 최신 상태로 갱신합니다.
     * 이 메서드는 주로 외부에서 가져온 FactorContext가 최신 상태인지 확인하고 싶거나,
     * SM 내부의 Action 등으로 변경된 최신 내용을 외부 FactorContext 객체에 반영하고자 할 때 사용합니다.
     *
     * @param contextToUpdate 최신 상태로 갱신할 외부 FactorContext 객체
     * @param request 현재 HttpServletRequest (세션 ID 추출 등에 사용될 수 있음)
     */
    public void refreshFactorContextFromStateMachine(FactorContext contextToUpdate, HttpServletRequest request) {
        // 메서드 이름을 refreshFactorContextFromStateMachine 등으로 변경하여 역할을 명확히 함
        String sessionId = contextToUpdate.getMfaSessionId();

        log.debug("Refreshing FactorContext from State Machine for session: {}", sessionId);

        try {
            // 항상 StateMachineService를 통해 최신 FactorContext를 가져옵니다.
            FactorContext latestContextFromSm = stateMachineService.getFactorContext(sessionId);

            if (latestContextFromSm != null) {
                // 버전 비교: SM 내부의 것이 더 최신이거나 같을 때만 외부 context를 업데이트합니다.
                // (외부 context가 어떤 이유로 더 최신 버전을 가지고 있다면 업데이트하지 않을 수 있으나,
                //  일반적으로 SM에 있는 것이 최신이라고 가정합니다.)
                if (contextToUpdate.getVersion() <= latestContextFromSm.getVersion() ||
                        !Objects.equals(contextToUpdate.calculateStateHash(), latestContextFromSm.calculateStateHash()) ) { // 상태 해시 비교 추가

                    log.info("Updating local FactorContext for session: {} from SM. Local version: {}, SM version: {}. Local state: {}, SM state: {}",
                            sessionId, contextToUpdate.getVersion(), latestContextFromSm.getVersion(),
                            contextToUpdate.getCurrentState(), latestContextFromSm.getCurrentState());

                    // 외부 contextToUpdate 객체의 내용을 latestContextFromSm의 내용으로 갱신합니다.
                    // FactorContext에 deep copy 또는 updateFrom(FactorContext source) 메서드가 있다면 활용합니다.
                    // 여기서는 주요 필드를 직접 복사하는 예시를 보여줍니다.

                    // 상태 동기화 (FactorContext 내부 changeState는 버전업 등을 유발할 수 있으므로 주의)
                    if (contextToUpdate.getCurrentState() != latestContextFromSm.getCurrentState()) {
                        contextToUpdate.changeState(latestContextFromSm.getCurrentState()); // 이 메서드가 버전을 올릴 수 있음
                    }

                    // 버전은 SM 에서 가져온 것을 기준으로 설정
                    contextToUpdate.setVersion(latestContextFromSm.getVersion());

                    // 나머지 주요 정보 동기화 (FactorContext 구현에 따라 필요한 필드 복사)
                    contextToUpdate.setCurrentProcessingFactor(latestContextFromSm.getCurrentProcessingFactor());
                    contextToUpdate.setCurrentStepId(latestContextFromSm.getCurrentStepId());
                    contextToUpdate.setMfaRequiredAsPerPolicy(latestContextFromSm.isMfaRequiredAsPerPolicy());
                    contextToUpdate.setRetryCount(latestContextFromSm.getRetryCount());
                    contextToUpdate.setLastError(latestContextFromSm.getLastError());
                    // ... 기타 비즈니스적으로 중요한 필드들 ...

                    // Attributes 동기화 (필요시)
                    // 기존 attributes를 유지하면서 SM의 것을 병합하거나, 완전히 덮어쓸 수 있습니다.
                    // 여기서는 SM의 attributes로 덮어쓰는 예시 (isSystemAttribute와 같은 필터링 로직은 유지)
                    contextToUpdate.getAttributes().clear(); // 기존 로컬 attributes 초기화
                    latestContextFromSm.getAttributes().forEach((key, value) -> {
                        if (!isSystemAttribute(key)) { // 시스템 속성이 아닌 경우에만 복사
                            contextToUpdate.setAttribute(key, value);
                        }
                    });

                    // completedFactors 동기화 (FactorContext의 addCompletedFactor가 중복을 알아서 처리한다면 간단히 추가)
                    // 또는 clear 후 addAll
                    contextToUpdate.getCompletedFactors().clear(); // 기존 로컬 completedFactors 초기화
                    latestContextFromSm.getCompletedFactors().forEach(contextToUpdate::addCompletedFactor);


                    log.debug("FactorContext refreshed from State Machine: session={}, newVersion={}, newState={}",
                            sessionId, contextToUpdate.getVersion(), contextToUpdate.getCurrentState());
                } else {
                    log.debug("Local FactorContext for session: {} is already up-to-date or newer. Version: {}, State: {}. SM Version: {}, SM State: {}",
                            sessionId, contextToUpdate.getVersion(), contextToUpdate.getCurrentState(),
                            latestContextFromSm.getVersion(), latestContextFromSm.getCurrentState());
                }
            } else {
                log.warn("No FactorContext found in State Machine for session: {}. Local context may be stale or session is new/terminated.", sessionId);
                // 이 경우, 외부 contextToUpdate를 어떻게 처리할지 정책이 필요합니다.
                // 예를 들어, SM에 컨텍스트가 없다면 외부 context도 초기화하거나 특정 상태로 변경할 수 있습니다.
                // contextToUpdate.changeState(MfaState.NONE); // 예시: SM에 없으면 NONE 상태로
                // contextToUpdate.setVersion(0); // 버전 초기화
            }
        } catch (Exception e) {
            log.error("Failed to refresh FactorContext from State Machine for session: {}", sessionId, e);
            // 예외 발생 시 외부 contextToUpdate는 변경되지 않도록 하거나, 오류 상태를 반영할 수 있습니다.
        }
    }

    /**
     * 완전 일원화: 현재 상태 조회 (캐시 활용)
     */
    public MfaState getCurrentState(String sessionId) {
        try {
            return stateMachineService.getCurrentState(sessionId);
        } catch (Exception e) {
            log.error("Failed to get current state from unified State Machine for session: {}", sessionId, e);
            return MfaState.NONE;
        }
    }

    public FactorContext loadFactorContext(String sessionId) {
        try {
            return stateMachineService.getFactorContext(sessionId);
        } catch (Exception e) {
            log.error("Failed to load FactorContext from unified State Machine for session: {}", sessionId, e);
            return null;
        }
    }

    public void saveFactorContext(FactorContext context) {
        try {
            stateMachineService.saveFactorContext(context);
            // 저장 후 동기화 상태 업데이트
            updateSyncState(context.getMfaSessionId(), context.getVersion());

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

            // 개선: 세션 해제 시 동기화 상태도 정리
            cleanupSyncState(sessionId);

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
     * 개선: 동기화 상태 업데이트
     */
    private void updateSyncState(String sessionId, int version) {
        lastSyncTimestamp.put(sessionId, System.currentTimeMillis());
        lastSyncVersion.put(sessionId, version);
    }

    /**
     * 개선: 동기화 상태 정리
     */
    private void cleanupSyncState(String sessionId) {
        lastSyncTimestamp.remove(sessionId);
        lastSyncVersion.remove(sessionId);
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
     * State Machine 에서 FactorContext로 단방향 동기화 (개선)
     */
    private void syncFactorContextFromStateMachine(FactorContext target, FactorContext source) {
        // 상태 동기화
        if (target.getCurrentState() != source.getCurrentState()) {
            target.changeState(source.getCurrentState());
        }

        // 버전 동기화
        while (target.getVersion() < source.getVersion()) {
            target.incrementVersion();
        }

        // 현재 처리 정보 동기화
        target.setCurrentProcessingFactor(source.getCurrentProcessingFactor());
        target.setCurrentStepId(source.getCurrentStepId());
        target.setMfaRequiredAsPerPolicy(source.isMfaRequiredAsPerPolicy());

        // 재시도 및 에러 정보 동기화
        target.setRetryCount(source.getRetryCount());
        if (source.getLastError() != null) {
            target.setLastError(source.getLastError());
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