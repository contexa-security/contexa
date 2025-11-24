package io.contexa.contexaidentity.controller;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * MfaApiController
 *
 * ⚠️ DEPRECATED: 이 컨트롤러는 MfaContinuationFilter와 중복됩니다.
 *
 * 마이그레이션 가이드:
 * - 모든 /api/mfa/* 엔드포인트는 /mfa/*로 이동
 * - MfaContinuationFilter가 Content-Type에 따라 JSON/HTML 응답
 * - SDK는 /mfa/* 엔드포인트 사용으로 변경 필요
 *
 * 제거 예정 메서드:
 * - selectFactor() → MfaContinuationFilter.handleFactorSelection()
 * - cancel() → MfaContinuationFilter.handleCancelMfa()
 * - getMfaStatus() → MfaContinuationFilter.handleStatusCheck()
 * - requestOttCode() → MfaContinuationFilter.handleChallengeInitiation()
 * - getFactorContext() → MfaContinuationFilter.handleMfaInitiation()
 *
 * 유지 메서드:
 * - getEndpointConfig() → SDK 초기화용 (별도 유틸리티로 이동 예정)
 *
 * @deprecated SDK 엔드포인트 변경 후 제거 예정
 */
@Slf4j
@Deprecated
@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
@ConditionalOnBean({MfaStateMachineIntegrator.class, AuthUrlProvider.class})
public class MfaApiController {

    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final AuthUrlProvider authUrlProvider;

    /**
     * 완전 일원화: MFA 팩터 선택 API
     */
    @PostMapping("/select-factor")
    public ResponseEntity<Map<String, Object>> selectFactor(@RequestBody Map<String, String> request,
                                                            HttpServletRequest httpRequest) {
        String factorType = request.get("factor");

        // 입력 검증
        if (!StringUtils.hasText(factorType)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "MISSING_FACTOR",
                    "Factor type is required", null);
        }

        // 완전 일원화: State Machine 통합자에서 FactorContext 로드
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_MFA_SESSION",
                    "Invalid or expired MFA session", ctx);
        }

        // 상태 검증 - 팩터 선택 가능한 상태인지 확인
        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            log.warn("Factor selection attempted in invalid state: {} for session: {}",
                    ctx.getCurrentState(), ctx.getMfaSessionId());
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_STATE",
                    "Cannot select factor in current state: " + ctx.getCurrentState(), ctx);
        }

        // 요청된 팩터가 사용 가능한지 확인
        AuthType requestedFactorType;
        try {
            requestedFactorType = AuthType.valueOf(factorType.toUpperCase());
        } catch (IllegalArgumentException e) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_FACTOR_TYPE",
                    "Invalid factor type: " + factorType, ctx);
        }

        // DSL에 정의된 팩터인지 확인
        if (!ctx.isFactorAvailable(requestedFactorType)) {
            log.warn("User {} attempted to select unavailable factor: {}. DSL available factors: {}",
                    ctx.getUsername(), requestedFactorType, ctx.getAvailableFactors());
            return createErrorResponse(HttpStatus.BAD_REQUEST, "FACTOR_NOT_AVAILABLE",
                    "시스템에서 지원하지 않는 팩터입니다: " + requestedFactorType, ctx);
        }

        try {
            // 선택된 팩터를 컨텍스트에 임시 저장 (State Machine에서 사용)
            ctx.setAttribute("selectedFactorType", requestedFactorType.name());

            // 완전 일원화: State Machine 통합자를 통해 이벤트 전송
            boolean accepted = stateMachineIntegrator.sendEvent(
                    MfaEvent.FACTOR_SELECTED, ctx, httpRequest
            );

            if (accepted) {
                String nextStepUrl = determineNextStepUrl(ctx, httpRequest);

                Map<String, Object> successResponse = createSuccessResponse(
                        "FACTOR_SELECTED", "Factor selected successfully", ctx);
                successResponse.put("selectedFactor", requestedFactorType.name());
                successResponse.put("nextStepUrl", nextStepUrl);
                successResponse.put("currentState", ctx.getCurrentState().name());

                log.info("Factor {} selected successfully for user {} (session: {})",
                        requestedFactorType, ctx.getUsername(), ctx.getMfaSessionId());

                return ResponseEntity.ok(successResponse);
            } else {
                log.error("State Machine rejected FACTOR_SELECTED event for session: {} in state: {}",
                        ctx.getMfaSessionId(), ctx.getCurrentState());
                return createErrorResponse(HttpStatus.BAD_REQUEST, "EVENT_REJECTED",
                        "Invalid state for factor selection", ctx);
            }

        } catch (Exception e) {
            log.error("Error selecting factor {} for session: {}", factorType, ctx.getMfaSessionId(), e);

            // State Machine에 에러 이벤트 전송
            try {
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, ctx, httpRequest);
            } catch (Exception eventError) {
                log.error("Failed to send SYSTEM_ERROR event", eventError);
            }

            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "FACTOR_SELECTION_FAILED",
                    "Failed to select factor", ctx);
        }
    }

    /**
     * 완전 일원화: MFA 취소 API
     */
    @PostMapping("/cancel")
    public ResponseEntity<Map<String, Object>> cancelMfa(HttpServletRequest httpRequest) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_MFA_SESSION",
                    "Invalid or expired MFA session", null);
        }

        // 터미널 상태에서는 취소 불가
        if (ctx.getCurrentState().isTerminal()) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "ALREADY_TERMINAL",
                    "MFA process is already completed or terminated", ctx);
        }

        try {
            // 완전 일원화: State Machine 통합자를 통해 취소 이벤트 전송
            boolean accepted = stateMachineIntegrator.sendEvent(
                    MfaEvent.USER_ABORTED_MFA, ctx, httpRequest
            );

            if (accepted) {
                Map<String, Object> successResponse = createSuccessResponse(
                        "MFA_CANCELLED", "MFA cancelled successfully", ctx);
                successResponse.put("redirectUrl", getContextPath(httpRequest) + authUrlProvider.getPrimaryLoginPage());

                log.info("MFA cancelled by user {} (session: {})",
                        ctx.getUsername(), ctx.getMfaSessionId());

                // 세션 정리
                stateMachineIntegrator.cleanupSession(httpRequest);

                return ResponseEntity.ok(successResponse);
            } else {
                log.warn("State Machine rejected USER_ABORTED_MFA event for session: {} in state: {}",
                        ctx.getMfaSessionId(), ctx.getCurrentState());
                return createErrorResponse(HttpStatus.BAD_REQUEST, "CANCELLATION_REJECTED",
                        "Cannot cancel MFA in current state: " + ctx.getCurrentState(), ctx);
            }

        } catch (Exception e) {
            log.error("Error cancelling MFA for session: {}", ctx.getMfaSessionId(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "CANCELLATION_FAILED",
                    "Failed to cancel MFA", ctx);
        }
    }

    /**
     * 완전 일원화: MFA 상태 조회 API (새로 추가)
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getMfaStatus(HttpServletRequest httpRequest) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.NOT_FOUND, "NO_MFA_SESSION",
                    "No active MFA session found", null);
        }

        try {
            Map<String, Object> statusResponse = new HashMap<>();
            statusResponse.put("status", "ACTIVE");
            statusResponse.put("mfaSessionId", ctx.getMfaSessionId());
            statusResponse.put("username", ctx.getUsername());
            statusResponse.put("currentState", ctx.getCurrentState().name());
            statusResponse.put("flowType", ctx.getFlowTypeName());
            statusResponse.put("isTerminal", ctx.getCurrentState().isTerminal());
            statusResponse.put("availableFactors", ctx.getAvailableFactors());
            statusResponse.put("completedFactorsCount", ctx.getCompletedFactors().size());
            statusResponse.put("storageType", "UNIFIED_STATE_MACHINE");

            if (ctx.getCurrentProcessingFactor() != null) {
                statusResponse.put("currentProcessingFactor", ctx.getCurrentProcessingFactor().name());
                statusResponse.put("currentStepId", ctx.getCurrentStepId());
            }

            return ResponseEntity.ok(statusResponse);

        } catch (Exception e) {
            log.error("Error retrieving MFA status for session: {}", ctx.getMfaSessionId(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "STATUS_RETRIEVAL_FAILED",
                    "Failed to retrieve MFA status", ctx);
        }
    }

    /**
     * 완전 일원화: OTT 코드 재전송 API (새로 추가)
     */
    @PostMapping("/request-ott-code")
    public ResponseEntity<Map<String, Object>> requestOttCode(HttpServletRequest httpRequest) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_MFA_SESSION",
                    "Invalid or expired MFA session", null);
        }

        // OTT 팩터 처리 중인지 확인
        if (ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_FACTOR",
                    "OTT code request is only available during OTT factor processing", ctx);
        }

        try {
            // OTT 코드 재전송 이벤트 전송
            boolean accepted = stateMachineIntegrator.sendEvent(
                    MfaEvent.INITIATE_CHALLENGE, ctx, httpRequest
            );

            if (accepted) {
                Map<String, Object> successResponse = createSuccessResponse(
                        "OTT_CODE_REQUESTED", "OTT code has been resent", ctx);

                return ResponseEntity.ok(successResponse);
            } else {
                return createErrorResponse(HttpStatus.BAD_REQUEST, "REQUEST_REJECTED",
                        "Cannot request OTT code in current state", ctx);
            }

        } catch (Exception e) {
            log.error("Error requesting OTT code for session: {}", ctx.getMfaSessionId(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "OTT_REQUEST_FAILED",
                    "Failed to request OTT code", ctx);
        }
    }

    /**
     * 새로 추가: MFA Context 조회 API
     * SDK가 FactorContext 정보를 동적으로 가져올 수 있도록 지원
     */
    @GetMapping("/context")
    public ResponseEntity<Map<String, Object>> getFactorContext(HttpServletRequest httpRequest) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.NOT_FOUND, "NO_MFA_SESSION",
                    "No active MFA session found", null);
        }

        try {
            Map<String, Object> contextResponse = new HashMap<>();
            contextResponse.put("mfaSessionId", ctx.getMfaSessionId());
            contextResponse.put("username", ctx.getUsername());
            contextResponse.put("currentState", ctx.getCurrentState().name());
            contextResponse.put("flowType", ctx.getFlowTypeName());
            contextResponse.put("isTerminal", ctx.getCurrentState().isTerminal());

            // DSL 사용 가능한 팩터 목록 (SDK가 UI 렌더링에 사용)
            List<String> availableFactorNames = ctx.getAvailableFactors().stream()
                    .map(AuthType::name)
                    .collect(Collectors.toList());
            contextResponse.put("availableFactors", availableFactorNames);

            // 완료된 팩터 목록
            List<String> completedFactorNames = ctx.getCompletedFactors().stream()
                    .filter(step -> step.getAuthType() != null)
                    .map(step -> step.getAuthType().name())
                    .collect(Collectors.toList());
            contextResponse.put("completedFactors", completedFactorNames);
            contextResponse.put("completedFactorsCount", completedFactorNames.size());

            // 현재 처리 중인 팩터 정보
            if (ctx.getCurrentProcessingFactor() != null) {
                contextResponse.put("currentProcessingFactor", ctx.getCurrentProcessingFactor().name());
                contextResponse.put("currentStepId", ctx.getCurrentStepId());
            }

            // State Machine 메타데이터
            contextResponse.put("storageType", "UNIFIED_STATE_MACHINE");
            contextResponse.put("timestamp", System.currentTimeMillis());

            log.debug("MFA context retrieved for session: {}, state: {}",
                    ctx.getMfaSessionId(), ctx.getCurrentState());

            return ResponseEntity.ok(contextResponse);

        } catch (Exception e) {
            log.error("Error retrieving MFA context for session: {}", ctx.getMfaSessionId(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "CONTEXT_RETRIEVAL_FAILED",
                    "Failed to retrieve MFA context", ctx);
        }
    }

    /**
     * 새로 추가: Endpoint Configuration 조회 API
     * SDK가 런타임에 모든 엔드포인트 URL을 로드할 수 있도록 지원
     *
     * 중앙 집중식 URL 관리 시스템 (AuthUrlProvider) 사용
     */
    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> getEndpointConfig() {
        try {
            // AuthUrlProvider의 getAllUiPageUrls() 메서드 활용
            Map<String, Object> config = authUrlProvider.getAllUiPageUrls();

            log.debug("Endpoint configuration retrieved successfully from AuthUrlProvider");

            return ResponseEntity.ok(config);

        } catch (Exception e) {
            log.error("Error retrieving endpoint configuration", e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "CONFIG_RETRIEVAL_FAILED",
                    "Failed to retrieve endpoint configuration", null);
        }
    }

    // === 유틸리티 메서드들 ===

    /**
     * 완전 일원화: MFA 컨텍스트 유효성 검증
     */
    private boolean isValidMfaContext(FactorContext ctx) {
        return ctx != null &&
                StringUtils.hasText(ctx.getUsername()) &&
                StringUtils.hasText(ctx.getMfaSessionId()) &&
                !ctx.getCurrentState().isTerminal();
    }

    /**
     * 완전 일원화: 다음 단계 URL 결정 (설정 기반)
     */
    private String determineNextStepUrl(FactorContext ctx, HttpServletRequest request) {
        String contextPath = getContextPath(request);
        AuthType currentFactor = ctx.getCurrentProcessingFactor();

        if (currentFactor == null) {
            return contextPath + authUrlProvider.getMfaSelectFactor();
        }

        return switch (currentFactor) {
            case OTT -> contextPath + authUrlProvider.getOttRequestCodeUi();
            case PASSKEY -> contextPath + authUrlProvider.getPasskeyChallengeUi();
            default -> {
                log.warn("Unknown factor type for next step determination: {}", currentFactor);
                yield contextPath + authUrlProvider.getMfaSelectFactor();
            }
        };
    }

    /**
     * 성공 응답 생성
     */
    private Map<String, Object> createSuccessResponse(String status, String message, FactorContext ctx) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", status);
        response.put("message", message);
        response.put("timestamp", System.currentTimeMillis());
        response.put("storageType", "UNIFIED_STATE_MACHINE");

        if (ctx != null) {
            response.put("mfaSessionId", ctx.getMfaSessionId());
            response.put("currentState", ctx.getCurrentState().name());
        }

        return response;
    }

    /**
     * 에러 응답 생성
     */
    private ResponseEntity<Map<String, Object>> createErrorResponse(HttpStatus status, String errorCode,
                                                                    String message, FactorContext ctx) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", errorCode);
        errorResponse.put("message", message);
        errorResponse.put("timestamp", System.currentTimeMillis());
        errorResponse.put("storageType", "UNIFIED_STATE_MACHINE");

        if (ctx != null) {
            errorResponse.put("mfaSessionId", ctx.getMfaSessionId());
            errorResponse.put("currentState", ctx.getCurrentState().name());
        }

        return ResponseEntity.status(status).body(errorResponse);
    }

    /**
     * Context Path 조회
     */
    private String getContextPath(HttpServletRequest request) {
        return request.getContextPath();
    }
}