package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.hcad.service.HCADContextExtractor;
// AI Native v4.0: HCADVectorIntegrationService import 제거 (클래스 삭제됨)
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * MFA 인증 성공 처리 핸들러 (OAuth2/JWT 토큰 기반)
 *
 * 토큰 발급과 응답 처리를 담당하며, 사용자 커스텀 로직을 위한 확장점 제공
 * AbstractTokenBasedSuccessHandler를 상속받아 토큰 생성 로직 재사용
 */
@Slf4j
public abstract class AbstractMfaAuthenticationSuccessHandler extends AbstractTokenBasedSuccessHandler implements ApplicationEventPublisherAware {

    private final MfaSessionRepository sessionRepository;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private ApplicationEventPublisher eventPublisher;
    private RedisTemplate<String, Object> redisTemplate;

    // AI Native v3.5.0: MFA 성공 시 Baseline 학습을 위한 서비스
    private BaselineLearningService baselineLearningService;

    protected AbstractMfaAuthenticationSuccessHandler(TokenService tokenService,
                                                      AuthResponseWriter responseWriter,
                                                      MfaSessionRepository sessionRepository,
                                                      MfaStateMachineIntegrator stateMachineIntegrator,
                                                      AuthContextProperties authContextProperties) {
        super(tokenService, responseWriter, authContextProperties);
        this.sessionRepository = sessionRepository;
        this.stateMachineIntegrator = stateMachineIntegrator;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }

    /**
     * AI Native v3.5.0: BaselineLearningService 선택적 주입
     *
     * MFA 성공 시 Baseline 학습을 위해 사용됩니다.
     * 선택적 주입으로, 서비스가 없어도 MFA 처리는 정상 동작합니다.
     */
    @Autowired(required = false)
    public void setBaselineLearningService(BaselineLearningService baselineLearningService) {
        this.baselineLearningService = baselineLearningService;
    }

    /**
     * 최종 인증 성공 처리 - 플랫폼 핵심 로직
     */
    protected final void handleFinalAuthenticationSuccess(HttpServletRequest request,
                                                          HttpServletResponse response,
                                                          Authentication finalAuthentication,
                                                          @Nullable FactorContext factorContext) throws IOException {

        if (response.isCommitted()) {
            log.warn("Response already committed for user: {}", finalAuthentication.getName());
            return;
        }

        // 1. StateType 결정 (OAuth2/Session 구분)
        StateType stateType = determineStateType(factorContext);
        log.debug("Determined StateType: {} for user: {}", stateType, finalAuthentication.getName());
        // 2. 조건부 토큰 생성 (OAuth2/JWT만 토큰 발급)
        TokenPair tokenPair;
        TokenTransportResult transportResult = null;

        if (stateType == StateType.OAUTH2) {
            String deviceId = factorContext != null ? (String) factorContext.getAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID) : null;
            tokenPair = createTokenPair(finalAuthentication, deviceId, request, response);
            String accessToken = tokenPair.getAccessToken();
            String refreshToken = tokenPair.getRefreshToken();

            // 토큰 전송 정보 준비
            transportResult = prepareTokenTransport(accessToken, refreshToken);

            log.debug("Tokens created for StateType: {}", stateType);
        } else {
            log.debug("Token creation skipped for StateType: {} (Session mode)", stateType);
        }

        // 3. 세션 정리
        if (factorContext != null && factorContext.getMfaSessionId() != null) {
            stateMachineIntegrator.releaseStateMachine(factorContext.getMfaSessionId());
            sessionRepository.removeSession(factorContext.getMfaSessionId(), request, response);

            // 3: 세션 해제 플래그 설정 (FilterChain에서 saveFactorContext 스킵 신호)
            request.setAttribute("mfaSessionReleased", true);
            log.debug("Set mfaSessionReleased flag for session: {}", factorContext.getMfaSessionId());
        }

        // 4. AI Native v3.5.0: MFA 성공 시 action 초기화 + Baseline 학습
        String userId = finalAuthentication.getName();
        resetActionOnMfaSuccess(userId, request);

        // 4. 응답 데이터 구성
        Map<String, Object> responseData = buildResponseData(
                stateType, transportResult, finalAuthentication, request, response);

        TokenTransportResult finalResult = TokenTransportResult.builder()
                .body(responseData)
                .cookiesToSet(transportResult != null ? transportResult.getCookiesToSet() : null)
                .cookiesToRemove(transportResult != null ? transportResult.getCookiesToRemove() : null)
                .headers(transportResult != null ? transportResult.getHeaders() : null)
                .build();

        // 5. 위임 핸들러 호출 (부모 클래스 공통 메서드 사용)
        executeDelegateHandler(request, response, finalAuthentication, finalResult);

        // 6. 하위 클래스 훅 호출
        if (!response.isCommitted()) {
            onFinalAuthenticationSuccess(request, response, finalAuthentication, finalResult);
        }

        // 7. 플랫폼 기본 응답
        if (!response.isCommitted()) {
            processDefaultResponse(response, finalResult);
        }
        
        // 8. Zero Trust 이벤트 발행 (Cold Start 해결 - AI 사전 분석)
        publishAuthenticationSuccessEvent(request, finalAuthentication, factorContext, finalResult);
    }

    /**
     * 하위 클래스 확장점
     */
    protected void onFinalAuthenticationSuccess(HttpServletRequest request,
                                                HttpServletResponse response,
                                                Authentication authentication,
                                                TokenTransportResult transportResult) throws IOException {
        // 하위 클래스에서 필요시 오버라이드
    }

    private void processDefaultResponse(HttpServletResponse response, TokenTransportResult result)
            throws IOException {
        // 쿠키 설정
        setCookies(response, result);

        // JSON 응답 작성
        writeJsonResponse(response, result.getBody());
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
        if (savedRequest != null) {
            this.requestCache.removeRequest(request, response);
            String redirectUrl = savedRequest.getRedirectUrl();

            // URL 검증: 유효한 애플리케이션 URL인지 확인
            if (isValidRedirectUrl(redirectUrl)) {
                return redirectUrl;
            } else {
                log.warn("Invalid saved redirect URL ignored: {}", redirectUrl);
            }
        }

        // AuthUrlConfig에서 MFA 성공 URL 가져오기
        return request.getContextPath() + authContextProperties.getUrls().getMfa().getSuccess();
    }

    /**
     * Redirect URL 유효성 검증
     * Chrome DevTools, .well-known, favicon 등 내부 요청 필터링
     *
     * @param url 검증할 URL
     * @return 유효한 URL이면 true, 그렇지 않으면 false
     */
    private boolean isValidRedirectUrl(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }

        // 제외할 패턴들
        String[] invalidPatterns = {
            "/.well-known/",
            "/favicon.ico",
            "chrome-extension://",
            "about:",
            "data:",
            "blob:",
            "javascript:"
        };

        for (String pattern : invalidPatterns) {
            if (url.contains(pattern)) {
                return false;
            }
        }

        return true;
    }

    /**
     * AbstractTokenBasedSuccessHandler의 abstract 메서드 구현
     * MFA는 자체 로직을 사용하므로 단순히 기본 URL 반환
     */
    @Override
    protected String determineTargetUrl(HttpServletRequest request) {
        return request.getContextPath() + authContextProperties.getUrls().getMfa().getSuccess();
    }

    /**
     * AbstractTokenBasedSuccessHandler의 abstract 메서드 구현
     * MFA는 자체 buildResponseData 메서드를 사용하므로 stub 구현
     */
    @Override
    protected Map<String, Object> buildResponseData(TokenTransportResult transportResult,
                                                     Authentication authentication,
                                                     HttpServletRequest request) {
        // MFA는 handleFinalAuthenticationSuccess에서 자체 buildResponseData 호출
        // 이 메서드는 직접 호출되지 않음
        return new HashMap<>();
    }

    /**
     * StateType 결정 - OAuth2/Session 구분
     *
     * @param factorContext FactorContext (nullable)
     * @return 결정된 StateType
     */
    private StateType determineStateType(@Nullable FactorContext factorContext) {
        // 1. FactorContext에서 직접 StateConfig 확인
        if (factorContext != null && factorContext.getStateConfig() != null) {
            return factorContext.getStateConfig().stateType();
        }

        // 2. Fallback: Global 기본값 사용
        StateType globalDefault = authContextProperties.getStateType();
        log.debug("StateConfig not found in FactorContext, using global default: {}", globalDefault);
        return globalDefault;
    }

    /**
     * 응답 데이터 구성 - StateType별로 다르게 구성
     *
     * @param stateType StateType (OAuth2/JWT/Session)
     * @param transportResult 토큰 전송 정보 (nullable for Session mode)
     * @param authentication 인증 객체
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @return 응답 데이터 Map
     */
    private Map<String, Object> buildResponseData(
            StateType stateType,
            @Nullable TokenTransportResult transportResult,
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) {

        Map<String, Object> responseData = new HashMap<>();

        // OAuth2/JWT 모드: 토큰 포함
        if (stateType == StateType.OAUTH2) {
            if (transportResult != null && transportResult.getBody() != null) {
                responseData.putAll(transportResult.getBody());
            }
        }

        // 공통 응답 데이터
        responseData.put("authenticated", true);  // Spring Security WebAuthn 호환성
        responseData.put("status", "MFA_COMPLETED");
        responseData.put("message", "인증이 완료되었습니다.");
        responseData.put("redirectUrl", determineTargetUrl(request, response, authentication));
        responseData.put("stateType", stateType.name());

        log.debug("Response data built for StateType: {}, contains tokens: {}",
                stateType, responseData.containsKey("accessToken"));

        return responseData;
    }
    
    /**
     * Zero Trust를 위한 인증 성공 이벤트 발행
     * 모든 성공한 인증을 AI가 실시간 분석하여 이상 패턴 감지
     */
    private void publishAuthenticationSuccessEvent(HttpServletRequest request,
                                                   Authentication authentication,
                                                   @Nullable FactorContext factorContext,
                                                   TokenTransportResult transportResult) {
        try {
            if (eventPublisher == null) {
                log.debug("ApplicationEventPublisher not available, skipping event publication");
                return;
            }
            
            UserDto userDto = (UserDto) authentication.getPrincipal();

            // 이벤트 빌더 생성
            AuthenticationSuccessEvent.AuthenticationSuccessEventBuilder builder = 
                AuthenticationSuccessEvent.builder()
                    .eventId(java.util.UUID.randomUUID().toString())
                    .userId(userDto.getUsername())  // Zero Trust를 위한 사용자 식별자 (username)
                    .username(userDto.getUsername())
                    .sessionId(request.getSession(false) != null ? request.getSession().getId() : null)
                    .eventTimestamp(java.time.LocalDateTime.now())
                    .sourceIp(extractClientIp(request))
                    .userAgent(request.getHeader("User-Agent"))
                    .authenticationType(factorContext != null && factorContext.isCompleted() ? "MFA" : "PRIMARY");
            
            // FactorContext 에서 추가 정보 추출
            if (factorContext != null) {
                builder.mfaCompleted(factorContext.isCompleted())
                       .deviceId((String) factorContext.getAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID))
                       .mfaMethod(factorContext.getCurrentProcessingFactor() != null ?
                                 factorContext.getCurrentProcessingFactor().toString() : null);

                // AI 위험 평가 정보
                Double aiRiskScore = (Double) factorContext.getAttribute(FactorContextAttributes.Policy.AI_RISK_SCORE);
                if (aiRiskScore != null) {
                    builder.trustScore(1.0 - aiRiskScore); // 위험 점수를 신뢰 점수로 변환
                }

                // 이상 징후 감지
                Boolean blocked = (Boolean) factorContext.getAttribute(FactorContextAttributes.StateControl.BLOCKED);
                builder.anomalyDetected(blocked != null && blocked);
                
                // 세션 컨텍스트
                Map<String, Object> sessionContext = new HashMap<>();
                sessionContext.put("mfaSessionId", factorContext.getMfaSessionId());
                sessionContext.put("currentState", factorContext.getCurrentState());
                sessionContext.put("availableFactors", factorContext.getAvailableFactors());
                builder.sessionContext(sessionContext);
            }
            
            // 추가 메타데이터
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("requestPath", request.getRequestURI());
            metadata.put("httpMethod", request.getMethod());
            if (transportResult != null && transportResult.getBody() != null) {
                metadata.put("authenticationResult", transportResult.getBody().get("status"));
            }
            builder.metadata(metadata);

            // 이벤트 발행
            AuthenticationSuccessEvent event = builder.build();
            eventPublisher.publishEvent(event);
            
            log.debug("Published authentication success event for user: {}, eventId: {}", 
                     userDto.getUsername(), event.getEventId());
            
        } catch (Exception e) {
            // 이벤트 발행 실패가 인증 프로세스를 중단시키지 않도록 예외 처리
            log.error("Failed to publish authentication success event", e);
        }
    }
    
    /**
     * MFA 진행 상황 정보 생성
     *
     * @param currentStep 현재 단계 (1부터 시작)
     * @param totalSteps 전체 단계 수
     * @return progress 정보 Map
     */
    protected Map<String, Object> createProgressInfo(int currentStep, int totalSteps) {
        Map<String, Object> progress = new HashMap<>();
        progress.put("current", currentStep);
        progress.put("total", totalSteps);
        progress.put("percentage", (int) Math.round((currentStep / (double) totalSteps) * 100));
        return progress;
    }

    /**
     * Factor 상세 정보 생성 (displayName, icon 포함)
     *
     * @param factorType Factor 타입 (예: "OTT", "PASSKEY")
     * @return Factor 상세 정보 Map
     */
    protected Map<String, Object> createFactorDetail(String factorType) {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", factorType);

        // displayName과 icon 설정
        switch (factorType.toUpperCase()) {
            case "OTT":
                detail.put("displayName", "이메일 인증 코드");
                detail.put("icon", "email");
                break;
            case "PASSKEY":
                detail.put("displayName", "Passkey 생체 인증");
                detail.put("icon", "fingerprint");
                break;
            case "TOTP":
                detail.put("displayName", "인증 앱 (TOTP)");
                detail.put("icon", "app");
                break;
            case "SMS":
                detail.put("displayName", "SMS 인증");
                detail.put("icon", "phone");
                break;
            default:
                detail.put("displayName", factorType);
                detail.put("icon", "security");
        }

        return detail;
    }

    /**
     * Phase 2.2: errorEventRecommendation 처리 공통 메서드
     *
     * Action에서 예외 발생 시 설정한 errorEventRecommendation을 읽어서
     * State Machine에 이벤트를 전송합니다.
     *
     * @param factorContext FactorContext
     * @param request HttpServletRequest
     * @param sessionId 세션 ID (로깅용)
     * @return errorEventRecommendation이 처리되었으면 true, 없거나 실패하면 false
     */
    protected boolean processErrorEventRecommendation(FactorContext factorContext,
                                                      HttpServletRequest request,
                                                      String sessionId) {
        if (factorContext == null) {
            return false;
        }

        MfaEvent errorEvent = (MfaEvent) factorContext.getAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION);

        if (errorEvent != null) {
            log.debug("Processing error event recommendation: {} for session: {}",
                     errorEvent, sessionId);

            try {
                boolean errorEventSent = stateMachineIntegrator.sendEvent(errorEvent, factorContext, request);

                if (errorEventSent) {
                    // Clear the recommendation after successful processing
                    factorContext.removeAttribute("errorEventRecommendation");
                    log.debug("Error event {} processed successfully for session: {}",
                             errorEvent, sessionId);
                    return true;
                } else {
                    log.error("Failed to send error event {} for session: {}", errorEvent, sessionId);
                }
            } catch (Exception sendError) {
                log.error("Failed to process error event recommendation for session: {}",
                         sessionId, sendError);
            }
        }

        return false;
    }

    /**
     * AI Native v3.5.0: MFA 성공 시 ALLOW 설정 + Baseline 학습
     *
     * MFA 성공 = 정상 사용자 확인 = ALLOW 획득
     * - 재분석 불필요 (LLM 호출 비용/시간 절약)
     * - ALLOW 획득 지점에서 직접 Baseline 학습
     *
     * Phase 8 수정: action 삭제 대신 ALLOW 설정
     * - 기존 문제: action 삭제 시 PENDING_ANALYSIS 상태가 되어 사용자 영구 제한
     * - 해결: action을 "ALLOW"로 설정하여 ZeroTrustSecurityService에서 원래 권한 복원
     *
     * @param userId 사용자 ID
     * @param request HttpServletRequest (Baseline 학습용 컨텍스트)
     */
    private void resetActionOnMfaSuccess(String userId, HttpServletRequest request) {
        if (userId == null || userId.isBlank() || redisTemplate == null) {
            return;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);

            // 1. action을 ALLOW로 변경
            redisTemplate.opsForHash().put(analysisKey, "action", "ALLOW");

            // 2. TTL을 ALLOW의 TTL(1시간)로 갱신
            redisTemplate.expire(analysisKey, Duration.ofHours(1));

            // 3. Baseline 학습 수행 (ALLOW 획득 지점에서 직접 처리)
            learnBaselineOnMfaSuccess(userId, request);

            log.info("[MFA][AI Native v3.5.0] Action set to ALLOW with Baseline learning for user: {}",
                    userId);

        } catch (Exception e) {
            log.error("[MFA] Failed to set action to ALLOW for user: {}", userId, e);
        }
    }

    /**
     * MFA 성공 시 Baseline 학습
     *
     * AI Native v3.5.0: MFA 성공 = 정상 사용자 확인
     * - LLM 재분석 없이 직접 Baseline 학습
     * - SecurityDecision.ALLOW + SecurityEvent 생성하여 학습
     *
     * @param userId 사용자 ID
     * @param request HttpServletRequest (컨텍스트 추출용)
     */
    private void learnBaselineOnMfaSuccess(String userId, HttpServletRequest request) {
        if (baselineLearningService == null) {
            log.debug("[MFA] BaselineLearningService not available, skipping baseline learning");
            return;
        }

        try {
            // SecurityDecision 생성 (MFA 성공 = ALLOW, 최고 신뢰도)
            SecurityDecision decision = SecurityDecision.builder()
                .action(SecurityDecision.Action.ALLOW)
                .confidence(1.0)  // MFA 성공 = 최고 신뢰도
                .riskScore(0.0)   // MFA 성공 = 최저 위험도
                .reasoning("MFA authentication completed successfully")
                .build();

            // SecurityEvent 생성 (request에서 컨텍스트 추출)
            SecurityEvent event = SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .source(SecurityEvent.EventSource.IAM)
                .userId(userId)
                .sourceIp(extractClientIp(request))
                .sessionId(request.getSession(false) != null ?
                    request.getSession(false).getId() : null)
                .userAgent(request.getHeader("User-Agent"))
                .timestamp(LocalDateTime.now())
                .description("MFA authentication success - baseline learning")
                .build();

            // Baseline 학습 수행
            boolean learned = baselineLearningService.learnIfNormal(userId, decision, event);

            if (learned) {
                log.info("[MFA][Baseline] Baseline learned on MFA success: userId={}", userId);
            } else {
                log.debug("[MFA][Baseline] Baseline learning skipped: userId={}", userId);
            }

        } catch (Exception e) {
            log.warn("[MFA][Baseline] Failed to learn baseline on MFA success: userId={}", userId, e);
            // Baseline 학습 실패해도 MFA 성공 처리는 계속 진행
        }
    }
}