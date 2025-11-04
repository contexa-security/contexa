package io.contexa.contexaidentity.security.filter.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.properties.MfaSettings;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.MfaTimeUtils;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * 완전 일원화된 State Machine 기반 MFA 요청 처리기
 * - State Machine이 유일한 상태 저장소
 * - 모든 상태 변경은 State Machine을 통해서만 처리
 * - Context Persistence 완전 제거
 */
@Slf4j
public class StateMachineAwareMfaRequestHandler implements MfaRequestHandler {

    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSettings mfaSettings;
    private final AuthUrlProvider authUrlProvider;

    public StateMachineAwareMfaRequestHandler(MfaPolicyProvider mfaPolicyProvider,
                                              AuthContextProperties authContextProperties,
                                              AuthResponseWriter responseWriter,
                                              ApplicationContext applicationContext,
                                              MfaStateMachineIntegrator stateMachineIntegrator,
                                              AuthUrlProvider authUrlProvider) {
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.authContextProperties = authContextProperties;
        this.responseWriter = responseWriter;
        this.applicationContext = applicationContext;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.mfaSettings = authContextProperties.getMfa();
        this.authUrlProvider = authUrlProvider;

        log.info("StateMachineAwareMfaRequestHandler initialized with unified State Machine");
    }

    @Override
    public void handleRequest(MfaRequestType requestType, HttpServletRequest request,
                              HttpServletResponse response, FactorContext context,
                              FilterChain filterChain) throws ServletException, IOException {

        String sessionId = context.getMfaSessionId();
        long startTime = System.currentTimeMillis();

        log.debug("Unified State Machine handling {} request for session: {}", requestType, sessionId);

        try {
            // Step 1: 요청 타입별 처리
            processRequestByType(requestType, request, response, context, filterChain);

            // Step 2: 처리 결과를 State Machine에 저장
            finalizeRequestProcessing(context, startTime);

        } catch (Exception e) {
            log.error("Error in unified State Machine request handling for session: {}", sessionId, e);
            handleProcessingError(request, response, context, e);
        }
    }

    @Override
    public void handleTerminalContext(HttpServletRequest request, HttpServletResponse response,
                                      FactorContext context) throws ServletException, IOException {
        String sessionId = context.getMfaSessionId();
        MfaState currentState = context.getCurrentState();

        log.info("Handling terminal context for session: {}, state: {} via unified State Machine",
                sessionId, currentState);

        // State Machine에서 최신 상태 확인
        MfaState latestState = stateMachineIntegrator.getCurrentState(sessionId);
        if (latestState != currentState) {
            log.warn("State mismatch detected: context={}, stateMachine={}", currentState, latestState);
            context.changeState(latestState);
            currentState = latestState;
        }

        Map<String, Object> responseBody = createBaseResponse(context);
        responseBody.put("terminal", true);
        responseBody.put("finalState", currentState.name());
        responseBody.put("handlerType", "UNIFIED_STATE_MACHINE");

        switch (currentState) {
            case MFA_SUCCESSFUL:
                handleSuccessfulTermination(request, response, responseBody);
                break;

            case MFA_NOT_REQUIRED:
                handleMfaNotRequiredTermination(request, response, responseBody);
                break;

            case MFA_FAILED_TERMINAL:
            case MFA_RETRY_LIMIT_EXCEEDED:
                handleFailedTermination(request, response, responseBody);
                break;

            case MFA_SESSION_EXPIRED:
                handleExpiredTermination(request, response, responseBody);
                break;

            case MFA_CANCELLED:
                handleCancelledTermination(request, response, responseBody);
                break;

            case MFA_SYSTEM_ERROR:
                handleSystemErrorTermination(request, response, responseBody);
                break;

            default:
                handleUnknownTermination(request, response, responseBody, currentState);
                break;
        }

        // 터미널 상태 도달 시 State Machine 정리
        scheduleStateMachineCleanup(sessionId);
    }

    @Override
    public void handleGenericError(HttpServletRequest request, HttpServletResponse response,
                                   FactorContext context, Exception error) throws ServletException, IOException {
        String sessionId = context != null ? context.getMfaSessionId() : "unknown";
        log.error("Generic error in unified State Machine MFA handling for session: {}", sessionId, error);

        // State Machine에 시스템 에러 이벤트 전송
        if (context != null) {
            try {
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, context, request);
            } catch (Exception e) {
                log.error("Failed to send SYSTEM_ERROR event to State Machine", e);
            }
        }

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_PROCESSING_ERROR");
        errorResponse.put("message", "MFA 처리 중 시스템 오류가 발생했습니다.");
        errorResponse.put("timestamp", System.currentTimeMillis());
        errorResponse.put("handlerType", "UNIFIED_STATE_MACHINE");

        if (context != null) {
            errorResponse.put("mfaSessionId", context.getMfaSessionId());
            errorResponse.put("currentState", context.getCurrentState().name());
        }

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_PROCESSING_ERROR", error.getMessage(), request.getRequestURI(), errorResponse);
    }

    // === 핵심 처리 메서드들 ===


    /**
     * 요청 타입별 처리
     */
    private void processRequestByType(MfaRequestType requestType, HttpServletRequest request,
                                      HttpServletResponse response, FactorContext context,
                                      FilterChain filterChain) throws ServletException, IOException {
        switch (requestType) {
            case MFA_INITIATE:
                handleMfaInitiation(request, response, context);
                break;

            case FACTOR_SELECTION:
            case SELECT_FACTOR:
                handleFactorSelection(request, response, context);
                break;

            case CHALLENGE_INITIATION:
                handleChallengeInitiation(request, response, context);
                break;

            case FACTOR_VERIFICATION:
            case TOKEN_GENERATION:
                handleFactorVerification(request, response, context, filterChain);
                break;

            case STATUS_CHECK:
                handleStatusCheck(request, response, context);
                break;

            case SESSION_REFRESH:
                handleSessionRefresh(request, response, context);
                break;

            case CANCEL_MFA:
            case CANCEL:
                handleCancelMfa(request, response, context);
                break;

            case LOGIN_PROCESSING:
                // 로그인 처리는 다른 필터로 위임
                filterChain.doFilter(request, response);
                break;

            default:
                handleUnsupportedRequest(request, response, context, requestType);
                break;
        }
    }

    /**
     * 요청 처리 완료 후 최종화
     */
    private void finalizeRequestProcessing(FactorContext context, long startTime) {
        try {
            // 처리 시간 기록
            long processingTime = System.currentTimeMillis() - startTime;
            context.setAttribute("lastRequestProcessingTime", processingTime);

            // State Machine에 저장
            stateMachineIntegrator.saveFactorContext(context);

            log.debug("Request processing finalized for session: {} in {}ms",
                    context.getMfaSessionId(), processingTime);
        } catch (Exception e) {
            log.error("Error finalizing request processing for session: {}",
                    context.getMfaSessionId(), e);
        }
    }

    // === 개별 요청 처리기들 ===

    private void handleMfaInitiation(HttpServletRequest request, HttpServletResponse response,
                                     FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        log.debug("Handling MFA initiation for session: {}", sessionId);

        MfaState currentState = context.getCurrentState();
        String nextUrl = determineNextStepUrl(context, request);

        Map<String, Object> responseData = createSuccessResponse(context, "MFA_INITIATED",
                "MFA 프로세스가 시작되었습니다.");
        responseData.put("nextUrl", nextUrl);
        responseData.put("currentStep", currentState.name());

        if (currentState == MfaState.AWAITING_FACTOR_SELECTION) {
            responseData.put("availableFactors", context.getAvailableFactors());
        }

        responseWriter.writeSuccessResponse(response, responseData, HttpServletResponse.SC_OK);
    }

    /**
     * 팩터 선택 처리 - 향상된 상태 검증
     */
    private void handleFactorSelection(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        log.debug("Handling factor selection for session: {}", sessionId);

        // 포괄적인 상태 검증
        if (!isValidStateForFactorSelection(context)) {
            handleInvalidStateError(request, response, context, "INVALID_STATE_FOR_SELECTION",
                    "팩터 선택이 불가능한 상태입니다. 현재 상태: " + context.getCurrentState());
            return;
        }

        // 사용 가능한 팩터 존재 여부 확인
        if (context.getAvailableFactors().isEmpty()) {
            handleInvalidStateError(request, response, context, "NO_AVAILABLE_FACTORS",
                    "사용 가능한 MFA 팩터가 없습니다.");
            return;
        }

        // 선택된 팩터 추출 및 검증
        String selectedFactor = extractAndValidateSelectedFactor(request, response, context);
        if (selectedFactor == null) return; // 오류 응답 이미 처리됨

        // 선택된 팩터가 등록된 팩터 목록에 있는지 확인
        if (!isFactorRegistered(context, selectedFactor)) {
            handleInvalidStateError(request, response, context, "FACTOR_NOT_REGISTERED",
                    "선택한 팩터가 등록되어 있지 않습니다: " + selectedFactor);
            return;
        }

        // State Machine 이벤트 전송
        if (sendFactorSelectionEvent(context, request, selectedFactor)) {
            handleFactorSelectionSuccess(request, response, context, selectedFactor);
        } else {
            handleFactorSelectionFailure(request, response, context);
        }
    }

    /**
     * 팩터 사용 가능 여부 확인
     */
    private boolean isFactorRegistered(FactorContext context, String selectedFactor) {
        try {
            AuthType selectedAuthType = AuthType.valueOf(selectedFactor.toUpperCase());
            return context.getAvailableFactors().contains(selectedAuthType);
        } catch (IllegalArgumentException e) {
            log.warn("Invalid factor type: {}", selectedFactor);
            return false;
        }
    }

    /**
     * 챌린지 시작 처리 - 향상된 상태 검증
     */
    private void handleChallengeInitiation(HttpServletRequest request, HttpServletResponse response,
                                           FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        MfaSettings mfaSettings = authContextProperties.getMfa();

        log.debug("Handling challenge initiation for session: {}", sessionId);

        // 포괄적인 상태 검증
        if (!isValidStateForChallengeInitiation(context)) {
            handleInvalidStateError(request, response, context, "INVALID_STATE_FOR_CHALLENGE",
                    "챌린지 시작이 불가능한 상태입니다. 현재 상태: " + context.getCurrentState());
            return;
        }

        // 현재 처리 팩터 확인
        if (context.getCurrentProcessingFactor() == null) {
            handleInvalidStateError(request, response, context, "NO_PROCESSING_FACTOR",
                    "처리할 팩터가 선택되지 않았습니다.");
            return;
        }

        // 이전 챌린지가 아직 유효한지 확인
        if (hasActiveChallengeForFactor(context)) {
            log.info("Active challenge exists for session: {}, reusing existing challenge", sessionId);

            // 기존 챌린지 정보로 응답
            Object challengeTime = context.getAttribute("challengeInitiatedAt");
            Instant challengeStart = MfaTimeUtils.fromMillis((Long) challengeTime);
            Duration remaining = MfaTimeUtils.getRemainingChallengeTime(challengeStart, mfaSettings);

            Map<String, Object> reuseResponse = createSuccessResponse(context, "CHALLENGE_REUSED",
                    "기존 챌린지를 재사용합니다.");
            reuseResponse.put("challengeUrl", determineNextStepUrl(context, request));
            reuseResponse.put("factorType", context.getCurrentProcessingFactor());
            reuseResponse.put("remainingTimeMs", remaining.toMillis());
            reuseResponse.put("challengeReused", true);

            responseWriter.writeSuccessResponse(response, reuseResponse, HttpServletResponse.SC_OK);
            return; // 상태는 그대로 유지
        }

        boolean accepted = stateMachineIntegrator.sendEvent(MfaEvent.INITIATE_CHALLENGE, context, request);

        if (accepted) {
            // 챌린지 시작 시간 기록 - Action에서 설정한 값이 있으면 재사용
            Object existingChallengeTime = context.getAttribute("challengeInitiatedAt");
            Instant challengeStartTime;
            if (existingChallengeTime instanceof Long) {
                challengeStartTime = MfaTimeUtils.fromMillis((Long) existingChallengeTime);
                log.debug("[StateMachineAwareMfaRequestHandler] Reusing challengeInitiatedAt from Action: {} for session: {}",
                        existingChallengeTime, sessionId);
            } else {
                challengeStartTime = MfaTimeUtils.nowInstant();
                context.setAttribute("challengeInitiatedAt", MfaTimeUtils.toMillis(challengeStartTime));
                log.debug("[StateMachineAwareMfaRequestHandler] Set new challengeInitiatedAt: {} for session: {}",
                        MfaTimeUtils.toMillis(challengeStartTime), sessionId);
            }
            context.setAttribute("ottCodeSent", true); // OTT의 경우

            // 챌린지 만료 시간 계산
            Instant challengeExpiryTime = MfaTimeUtils.calculateChallengeExpiry(challengeStartTime, mfaSettings);
            Duration challengeDuration = MfaTimeUtils.getRemainingChallengeTime(challengeStartTime, mfaSettings);

            Map<String, Object> successResponse = createSuccessResponse(context, "CHALLENGE_INITIATED",
                    "챌린지가 시작되었습니다.");
            successResponse.put("factorType", context.getCurrentProcessingFactor());
            successResponse.put("challengeUrl", determineNextStepUrl(context, request));
            successResponse.put("challengeInitiatedAt", MfaTimeUtils.toMillis(challengeStartTime));
            successResponse.put("challengeInitiatedAtISO", MfaTimeUtils.toIsoString(challengeStartTime));
            successResponse.put("challengeExpiresAt", MfaTimeUtils.toMillis(challengeExpiryTime));
            successResponse.put("challengeExpiresAtISO", MfaTimeUtils.toIsoString(challengeExpiryTime));
            successResponse.put("challengeTimeoutMs", mfaSettings.getChallengeTimeoutMs());
            successResponse.put("remainingTimeMs", challengeDuration.toMillis());
            successResponse.put("remainingTimeDisplay", MfaTimeUtils.toDisplayString(challengeDuration));

            responseWriter.writeSuccessResponse(response, successResponse, HttpServletResponse.SC_OK);
        } else {
            handleInvalidStateError(request, response, context, "CHALLENGE_INITIATION_FAILED",
                    "챌린지 시작에 실패했습니다.");
        }
    }

    /**
     * 활성 챌린지 존재 여부 확인
     */
    private boolean hasActiveChallengeForFactor(FactorContext context) {
        Object challengeTime = context.getAttribute("challengeInitiatedAt");
        if (!(challengeTime instanceof Long)) {
            return false;
        }

        // 챌린지가 만료되지 않았다면 활성 상태
        return !mfaSettings.isChallengeExpired((Long) challengeTime);
    }

    /**
     * 기존 챌린지로 리다이렉트
     */
    private void redirectToExistingChallenge(HttpServletRequest request, HttpServletResponse response,
                                             FactorContext context) throws IOException {
        Map<String, Object> redirectResponse = createSuccessResponse(context, "EXISTING_CHALLENGE",
                "이미 활성화된 챌린지가 있습니다.");
        redirectResponse.put("challengeUrl", determineNextStepUrl(context, request));
        redirectResponse.put("factorType", context.getCurrentProcessingFactor());

        Object challengeTime = context.getAttribute("challengeInitiatedAt");
        if (challengeTime instanceof Long) {
            Instant challengeStart = MfaTimeUtils.fromMillis((Long) challengeTime);
            Duration remaining = MfaTimeUtils.getRemainingChallengeTime(challengeStart, mfaSettings);
            redirectResponse.put("remainingTimeMs", remaining.toMillis());
            redirectResponse.put("remainingTimeDisplay", MfaTimeUtils.toDisplayString(remaining));
        }

        responseWriter.writeSuccessResponse(response, redirectResponse, HttpServletResponse.SC_OK);
    }

    /**
     * 팩터 검증 처리 - 향상된 상태 검증
     */
    private void handleFactorVerification(HttpServletRequest request, HttpServletResponse response,
                                          FactorContext context, FilterChain filterChain)
            throws ServletException, IOException {
        String sessionId = context.getMfaSessionId();

        log.debug("Handling factor verification for session: {}", sessionId);

        // 개선: 포괄적인 상태 검증 사용
        if (!canProcessFactorVerification(context)) {
            handleInvalidStateError(request, response, context, "INVALID_STATE_FOR_VERIFICATION",
                    "팩터 검증이 불가능한 상태입니다. 현재 상태: " + context.getCurrentState());
            return;
        }

        // 개선: MfaSettings 활용한 챌린지 타임아웃 확인
        if (isChallengeExpiredUsingSettings(context)) {
            log.warn("Challenge expired for session: {}", sessionId);
            stateMachineIntegrator.sendEvent(MfaEvent.CHALLENGE_TIMEOUT, context, request);
            handleInvalidStateError(request, response, context, "CHALLENGE_EXPIRED",
                    "챌린지가 만료되었습니다. 다시 시도해주세요.");
            return;
        }

        // 개선: MfaSettings 활용한 재시도 제한 확인
        if (!isRetryAllowedUsingSettings(context)) {
            log.warn("Retry limit exceeded for session: {}", sessionId);
            stateMachineIntegrator.sendEvent(MfaEvent.RETRY_LIMIT_EXCEEDED, context, request);
            handleInvalidStateError(request, response, context, "RETRY_LIMIT_EXCEEDED",
                    "최대 재시도 횟수를 초과했습니다.");
            return;
        }

        // 추가: 팩터별 추가 검증
        if (!validateFactorSpecificRequirements(context)) {
            handleInvalidStateError(request, response, context, "FACTOR_REQUIREMENTS_NOT_MET",
                    "현재 팩터의 요구사항이 충족되지 않았습니다.");
            return;
        }

        // 검증 시작 시간 기록
        context.setAttribute("verificationStartTime", System.currentTimeMillis());

        log.debug("Delegating factor verification to specialized filter for session: {}", sessionId);
        filterChain.doFilter(request, response);
    }

    /**
     * 팩터별 특별 요구사항 검증
     */
    private boolean validateFactorSpecificRequirements(FactorContext context) {
        AuthType currentFactor = context.getCurrentProcessingFactor();

        if (currentFactor == null) {
            return false;
        }

        switch (currentFactor) {
            case OTT:
                // OTT 코드가 발송되었는지 확인
                Object ottSent = context.getAttribute("ottCodeSent");
                if (!(ottSent instanceof Boolean) || !(Boolean) ottSent) {
                    log.debug("OTT code not sent for session: {}", context.getMfaSessionId());
                    return false;
                }
                break;

            case PASSKEY:
                // Passkey 옵션이 생성되었는지 확인
                Object passkeyGenerated = context.getAttribute("passkeyOptionsGenerated");
                if (!(passkeyGenerated instanceof Boolean) || !(Boolean) passkeyGenerated) {
                    log.debug("Passkey options not generated for session: {}", context.getMfaSessionId());
                    return false;
                }
                break;

            default:
                // 다른 팩터들은 기본 검증만 수행
                break;
        }

        return true;
    }

    /**
     * 개선: MfaSettings를 활용한 챌린지 만료 확인
     */
    private boolean isChallengeExpiredUsingSettings(FactorContext context) {
        Object challengeStartTime = context.getAttribute("challengeInitiatedAt");
        if (challengeStartTime instanceof Long challengeStartTimeMs) {
            return mfaSettings.isChallengeExpired(challengeStartTimeMs);
        }
        return false;
    }

    /**
     * 개선: MfaSettings를 활용한 재시도 허용 확인
     */
    private boolean isRetryAllowedUsingSettings(FactorContext context) {
        int attempts = context.getAttemptCount(context.getCurrentProcessingFactor());
        return mfaSettings.isRetryAllowed(attempts);
    }

    private void handleStatusCheck(HttpServletRequest request, HttpServletResponse response,
                                   FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        MfaSettings mfaSettings = authContextProperties.getMfa();

        // State Machine에서 최신 상태 조회
        MfaState latestState = stateMachineIntegrator.getCurrentState(sessionId);

        // 시간 관련 정보 계산
        Duration remainingSessionTime = MfaTimeUtils.getRemainingSessionTime(context, mfaSettings);
        boolean sessionExpired = MfaTimeUtils.isSessionExpired(context, mfaSettings);

        Map<String, Object> statusResponse = createSuccessResponse(context, "STATUS_CHECK",
                "상태 조회가 완료되었습니다.");
        statusResponse.put("latestState", latestState.name());
        statusResponse.put("isTerminal", latestState.isTerminal());
        statusResponse.put("isWaitingForUserAction", latestState.isWaitingForUserAction());
        statusResponse.put("isProcessing", latestState.isProcessing());
        statusResponse.put("availableFactors", context.getAvailableFactors());
        statusResponse.put("completedFactorsCount", context.getCompletedFactors().size());
        statusResponse.put("statusCheckedAt", MfaTimeUtils.nowMillis());

        // 세션 상태 정보
        statusResponse.put("sessionExpired", sessionExpired);
        statusResponse.put("remainingSessionTimeMs", remainingSessionTime.toMillis());
        statusResponse.put("remainingSessionTimeDisplay", MfaTimeUtils.toDisplayString(remainingSessionTime));
        statusResponse.put("lastActivityTime", MfaTimeUtils.toMillis(context.getLastActivityTimestamp()));
        statusResponse.put("lastActivityTimeISO", MfaTimeUtils.toIsoString(context.getLastActivityTimestamp()));

        if (context.getCurrentProcessingFactor() != null) {
            statusResponse.put("currentProcessingFactor", context.getCurrentProcessingFactor().name());
            statusResponse.put("currentStepId", context.getCurrentStepId());

            // 챌린지 관련 정보
            Object challengeStartTimeObj = context.getAttribute("challengeInitiatedAt");
            if (challengeStartTimeObj instanceof Long challengeStartTimeMs) {
                Instant challengeStartTime = MfaTimeUtils.fromMillis(challengeStartTimeMs);
                Duration remainingChallengeTime = MfaTimeUtils.getRemainingChallengeTime(challengeStartTime, mfaSettings);
                boolean challengeExpired = MfaTimeUtils.isChallengeExpired(challengeStartTime, mfaSettings);

                statusResponse.put("challengeExpired", challengeExpired);
                statusResponse.put("remainingChallengeTimeMs", remainingChallengeTime.toMillis());
                statusResponse.put("remainingChallengeTimeDisplay", MfaTimeUtils.toDisplayString(remainingChallengeTime));
                statusResponse.put("challengeInitiatedAt", challengeStartTimeMs);
                statusResponse.put("challengeInitiatedAtISO", MfaTimeUtils.toIsoString(challengeStartTime));
            }

            // 재시도 정보
            int currentAttempts = context.getAttemptCount(context.getCurrentProcessingFactor());
            statusResponse.put("currentAttempts", currentAttempts);
            statusResponse.put("maxAttempts", mfaSettings.getMaxRetryAttempts());
            statusResponse.put("retriesRemaining", Math.max(0, mfaSettings.getMaxRetryAttempts() - currentAttempts));
            statusResponse.put("retryAllowed", mfaSettings.isRetryAllowed(currentAttempts));
        }

        responseWriter.writeSuccessResponse(response, statusResponse, HttpServletResponse.SC_OK);
    }

    private void handleSessionRefresh(HttpServletRequest request, HttpServletResponse response,
                                      FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        MfaSettings mfaSettings = authContextProperties.getMfa();

        // 세션 갱신이 필요한지 확인
        if (!MfaTimeUtils.needsSessionRefresh(context, mfaSettings)) {
            log.debug("Session refresh not needed for session: {}", sessionId);
        }

        // 세션 활동 시간 업데이트
        context.updateLastActivityTimestamp();

        // State Machine에 저장
        stateMachineIntegrator.saveFactorContext(context);

        // 타입 안전한 시간 계산
        Instant sessionExpiryTime = MfaTimeUtils.calculateSessionExpiry(context, mfaSettings);
        Duration remainingTime = MfaTimeUtils.getRemainingSessionTime(context, mfaSettings);

        Map<String, Object> refreshResponse = createSuccessResponse(context, "SESSION_REFRESHED",
                "세션이 갱신되었습니다.");
        refreshResponse.put("refreshedAt", MfaTimeUtils.nowMillis());
        refreshResponse.put("lastActivityTime", MfaTimeUtils.toMillis(context.getLastActivityTimestamp()));
        refreshResponse.put("sessionValidUntil", MfaTimeUtils.toMillis(sessionExpiryTime));
        refreshResponse.put("sessionValidUntilISO", MfaTimeUtils.toIsoString(sessionExpiryTime));
        refreshResponse.put("sessionValidUntilDisplay", MfaTimeUtils.toDisplayString(sessionExpiryTime));
        refreshResponse.put("remainingTimeMs", remainingTime.toMillis());
        refreshResponse.put("remainingTimeDisplay", MfaTimeUtils.toDisplayString(remainingTime));
        refreshResponse.put("sessionTimeoutMs", mfaSettings.getSessionTimeoutMs());

        responseWriter.writeSuccessResponse(response, refreshResponse, HttpServletResponse.SC_OK);
    }

    private void handleCancelMfa(HttpServletRequest request, HttpServletResponse response,
                                 FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        log.info("Handling MFA cancellation for session: {}", sessionId);

        boolean accepted = stateMachineIntegrator.sendEvent(MfaEvent.USER_ABORTED_MFA, context, request);

        if (accepted) {
            Map<String, Object> cancelResponse = createSuccessResponse(context, "MFA_CANCELLED",
                    "MFA가 사용자에 의해 취소되었습니다.");
            cancelResponse.put("cancelledAt", System.currentTimeMillis());
            cancelResponse.put("redirectUrl", request.getContextPath() + "/loginForm");

            responseWriter.writeSuccessResponse(response, cancelResponse, HttpServletResponse.SC_OK);

            // 세션 정리 스케줄링
            scheduleStateMachineCleanup(sessionId);
        } else {
            handleInvalidStateError(request, response, context, "CANCELLATION_FAILED",
                    "MFA 취소에 실패했습니다.");
        }
    }

    private void handleUnsupportedRequest(HttpServletRequest request, HttpServletResponse response,
                                          FactorContext context, MfaRequestType requestType) throws IOException {
        String sessionId = context.getMfaSessionId();
        log.warn("Unsupported request type: {} for session: {}", requestType, sessionId);

        Map<String, Object> errorResponse = createErrorResponse(context, "UNSUPPORTED_REQUEST",
                "지원하지 않는 요청 타입입니다: " + requestType.getDescription());
        errorResponse.put("requestType", requestType.name());
        errorResponse.put("supportedTypes", MfaRequestType.values());

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "UNSUPPORTED_REQUEST", "Unsupported request type", request.getRequestURI(), errorResponse);
    }

    // === 터미널 상태 처리기들 ===

    private void handleSuccessfulTermination(HttpServletRequest request, HttpServletResponse response,
                                             Map<String, Object> responseBody) throws IOException {
        responseBody.put("status", "MFA_COMPLETED");
        responseBody.put("message", "MFA 인증이 성공적으로 완료되었습니다.");
        responseBody.put("redirectUrl", request.getContextPath() + "/home");
        responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
    }

    private void handleMfaNotRequiredTermination(HttpServletRequest request, HttpServletResponse response,
                                                 Map<String, Object> responseBody) throws IOException {
        responseBody.put("status", "MFA_NOT_REQUIRED");
        responseBody.put("message", "MFA가 필요하지 않습니다.");
        responseBody.put("redirectUrl", request.getContextPath() + "/home");
        responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
    }

    private void handleFailedTermination(HttpServletRequest request, HttpServletResponse response,
                                         Map<String, Object> responseBody) throws IOException {
        responseBody.put("status", "MFA_FAILED");
        responseBody.put("message", "MFA 인증이 실패했습니다.");
        responseBody.put("redirectUrl", request.getContextPath() + "/loginForm");
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                "MFA_FAILED", "MFA 인증 실패", request.getRequestURI(), responseBody);
    }

    private void handleExpiredTermination(HttpServletRequest request, HttpServletResponse response,
                                          Map<String, Object> responseBody) throws IOException {
        responseBody.put("status", "SESSION_EXPIRED");
        responseBody.put("message", "MFA 세션이 만료되었습니다.");
        responseBody.put("redirectUrl", request.getContextPath() + "/loginForm");
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                "SESSION_EXPIRED", "세션 만료", request.getRequestURI(), responseBody);
    }

    private void handleCancelledTermination(HttpServletRequest request, HttpServletResponse response,
                                            Map<String, Object> responseBody) throws IOException {
        responseBody.put("status", "MFA_CANCELLED");
        responseBody.put("message", "사용자에 의해 MFA가 취소되었습니다.");
        responseBody.put("redirectUrl", request.getContextPath() + "/loginForm");
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "MFA_CANCELLED", "MFA 취소", request.getRequestURI(), responseBody);
    }

    private void handleSystemErrorTermination(HttpServletRequest request, HttpServletResponse response,
                                              Map<String, Object> responseBody) throws IOException {
        responseBody.put("status", "SYSTEM_ERROR");
        responseBody.put("message", "시스템 오류가 발생했습니다.");
        responseBody.put("redirectUrl", request.getContextPath() + "/loginForm");
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "SYSTEM_ERROR", "시스템 오류", request.getRequestURI(), responseBody);
    }

    private void handleUnknownTermination(HttpServletRequest request, HttpServletResponse response,
                                          Map<String, Object> responseBody, MfaState currentState) throws IOException {
        responseBody.put("status", "UNKNOWN_TERMINAL_STATE");
        responseBody.put("message", "알 수 없는 터미널 상태입니다: " + currentState);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "UNKNOWN_STATE", "알 수 없는 상태", request.getRequestURI(), responseBody);
    }

    // === 유틸리티 메서드들 ===

    /**
     * 팩터 선택 상태 검증 - 더 유연한 상태 지원
     */
    private boolean isValidStateForFactorSelection(FactorContext context) {
        MfaState currentState = context.getCurrentState();

        // 팩터 선택 가능한 모든 상태 포함
        return currentState == MfaState.AWAITING_FACTOR_SELECTION ||
                currentState == MfaState.PRIMARY_AUTHENTICATION_COMPLETED ||
                currentState == MfaState.FACTOR_VERIFICATION_COMPLETED;
    }

    /**
     * 챌린지 시작 상태 검증 - 더 포괄적인 지원
     */
    private boolean isValidStateForChallengeInitiation(FactorContext context) {
        MfaState currentState = context.getCurrentState();

        // 챌린지 시작 가능한 상태들
        return currentState == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION;
    }

    /**
     * 더 포괄적인 상태 검증
     */
    private boolean canProcessFactorVerification(FactorContext context) {
        MfaState state = context.getCurrentState();

        // 검증 처리 가능한 상태들
        boolean validState = state == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                state == MfaState.FACTOR_VERIFICATION_PENDING;

        if (!validState) {
            log.debug("Cannot process factor verification in state: {} for session: {}",
                    state, context.getMfaSessionId());
            return false;
        }

        // 추가 검증: 현재 처리 중인 팩터 존재 확인
        if (context.getCurrentProcessingFactor() == null) {
            log.debug("No current processing factor for session: {}", context.getMfaSessionId());
            return false;
        }

        return true;
    }

    private String extractAndValidateSelectedFactor(HttpServletRequest request, HttpServletResponse response,
                                                    FactorContext context) throws IOException {
        String selectedFactor = request.getParameter("factor");
        if (selectedFactor == null || selectedFactor.trim().isEmpty()) {
            Map<String, Object> errorResponse = createErrorResponse(context, "MISSING_FACTOR_PARAMETER",
                    "선택할 팩터를 지정해주세요.");
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "MISSING_PARAMETER", "Missing factor parameter", request.getRequestURI(), errorResponse);
            return null;
        }
        return selectedFactor.trim();
    }

    private boolean sendFactorSelectionEvent(FactorContext context, HttpServletRequest request, String selectedFactor) {
        try {
            // 선택된 팩터 정보 설정
            context.setAttribute("selectedFactor", selectedFactor);
            request.setAttribute("selectedFactor", selectedFactor);

            // State Machine 이벤트 전송
            return stateMachineIntegrator.sendEvent(MfaEvent.FACTOR_SELECTED, context, request);
        } catch (Exception e) {
            log.error("Failed to send factor selection event", e);
            return false;
        }
    }

    private void handleFactorSelectionSuccess(HttpServletRequest request, HttpServletResponse response,
                                              FactorContext context, String selectedFactor) throws IOException {
        // Phase 2: State Machine 이벤트 전송으로 다음 단계 결정 (수정은 Action에서)
        boolean determined = stateMachineIntegrator.sendEvent(
            MfaEvent.DETERMINE_NEXT_FACTOR, context, request
        );

        if (!determined) {
            log.warn("Failed to determine next factor for session: {}", context.getMfaSessionId());
        }

        Map<String, Object> successResponse = createSuccessResponse(context, "FACTOR_SELECTED",
                "팩터가 성공적으로 선택되었습니다.");
        successResponse.put("selectedFactor", selectedFactor);
        successResponse.put("nextStepUrl", determineNextStepUrl(context, request));
        successResponse.put("factorSelectedAt", System.currentTimeMillis());

        responseWriter.writeSuccessResponse(response, successResponse, HttpServletResponse.SC_OK);
    }

    private void handleFactorSelectionFailure(HttpServletRequest request, HttpServletResponse response,
                                              FactorContext context) throws IOException {
        handleInvalidStateError(request, response, context, "FACTOR_SELECTION_REJECTED",
                "팩터 선택이 거부되었습니다.");
    }

    private void handleInvalidStateError(HttpServletRequest request, HttpServletResponse response,
                                         FactorContext context, String errorCode, String message) throws IOException {
        Map<String, Object> errorResponse = createErrorResponse(context, errorCode, message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                errorCode, message, request.getRequestURI(), errorResponse);
    }

    private void handleProcessingError(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext context, Exception error) throws IOException {
        Map<String, Object> errorResponse = createErrorResponse(context, "REQUEST_PROCESSING_ERROR",
                "요청 처리 중 오류가 발생했습니다.");
        errorResponse.put("errorType", error.getClass().getSimpleName());
        errorResponse.put("errorMessage", error.getMessage());

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "REQUEST_PROCESSING_ERROR", error.getMessage(), request.getRequestURI(), errorResponse);
    }

    private Map<String, Object> createBaseResponse(FactorContext context) {
        Map<String, Object> response = new HashMap<>();
        response.put("mfaSessionId", context.getMfaSessionId());
        response.put("currentState", context.getCurrentState().name());
        response.put("timestamp", System.currentTimeMillis());
        response.put("handlerType", "UNIFIED_STATE_MACHINE");
        response.put("version", context.getVersion());
        return response;
    }

    private Map<String, Object> createSuccessResponse(FactorContext context, String status, String message) {
        Map<String, Object> response = createBaseResponse(context);
        response.put("status", status);
        response.put("message", message);
        response.put("success", true);
        return response;
    }

    private Map<String, Object> createErrorResponse(FactorContext context, String error, String message) {
        Map<String, Object> response = createBaseResponse(context);
        response.put("error", error);
        response.put("message", message);
        response.put("success", false);
        return response;
    }

    private String determineNextStepUrl(FactorContext context, HttpServletRequest request) {
        if (context.getCurrentProcessingFactor() == null) {
            return request.getContextPath() + authUrlProvider.getMfaSelectFactorUi();
        }

        return switch (context.getCurrentProcessingFactor()) {
            case OTT -> request.getContextPath() +
                    authUrlProvider.getOttRequestCodeUi();
            case PASSKEY -> request.getContextPath() +
                    authUrlProvider.getPasskeyChallengeUi();
            default -> request.getContextPath() + authUrlProvider.getMfaSelectFactorUi();
        };
    }

    private void scheduleStateMachineCleanup(String sessionId) {
        // 비동기로 State Machine 정리 스케줄링
        applicationContext.getBean("taskExecutor", java.util.concurrent.Executor.class)
                .execute(() -> {
                    try {
                        Thread.sleep(5000); // 5초 후 정리
                        stateMachineIntegrator.releaseStateMachine(sessionId);
                        log.info("State Machine cleanup completed for session: {}", sessionId);
                    } catch (Exception e) {
                        log.error("Error during State Machine cleanup for session: {}", sessionId, e);
                    }
                });
    }
}