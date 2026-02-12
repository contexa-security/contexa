package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
public abstract class AbstractMfaAuthenticationSuccessHandler extends AbstractTokenBasedSuccessHandler {

    private final MfaSessionRepository sessionRepository;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final ZeroTrustEventPublisher zeroTrustEventPublisher;
    private final ZeroTrustActionRedisRepository actionRedisRepository;
    private final SecurityLearningService securityLearningService;
    private final HcadProperties hcadProperties;

    protected AbstractMfaAuthenticationSuccessHandler(TokenService tokenService,
                                                      AuthResponseWriter responseWriter,
                                                      MfaSessionRepository sessionRepository,
                                                      MfaStateMachineIntegrator stateMachineIntegrator,
                                                      AuthContextProperties authContextProperties,
                                                      ZeroTrustEventPublisher zeroTrustEventPublisher,
                                                      ZeroTrustActionRedisRepository actionRedisRepository,
                                                      SecurityLearningService securityLearningService,
                                                      HcadProperties hcadProperties) {
        super(tokenService, responseWriter, authContextProperties);
        this.sessionRepository = sessionRepository;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
        this.actionRedisRepository = actionRedisRepository;
        this.securityLearningService = securityLearningService;
        this.hcadProperties = hcadProperties;
    }

    protected final void handleFinalAuthenticationSuccess(HttpServletRequest request,
                                                          HttpServletResponse response,
                                                          Authentication finalAuthentication,
                                                          @Nullable FactorContext factorContext) throws IOException {

        if (response.isCommitted()) {
            log.warn("Response already committed for user: {}", finalAuthentication.getName());
            return;
        }

        StateType stateType = determineStateType(factorContext);

        TokenPair tokenPair;
        TokenTransportResult transportResult = null;

        if (stateType == StateType.OAUTH2) {
            String deviceId = factorContext != null ? (String) factorContext.getAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID) : null;
            tokenPair = createTokenPair(finalAuthentication, deviceId, request, response);
            String accessToken = tokenPair.getAccessToken();
            String refreshToken = tokenPair.getRefreshToken();

            transportResult = prepareTokenTransport(accessToken, refreshToken);

        }

        if (factorContext != null && factorContext.getMfaSessionId() != null) {
            stateMachineIntegrator.releaseStateMachine(factorContext.getMfaSessionId());
            sessionRepository.removeSession(factorContext.getMfaSessionId(), request, response);

            request.setAttribute("mfaSessionReleased", true);
        }

        String userId = finalAuthentication.getName();
        if (factorContext != null && factorContext.isCompleted()) {
            resetActionOnMfaSuccess(userId, request);
        }

        Map<String, Object> responseData = buildResponseData(stateType, transportResult, request, response);
        TokenTransportResult finalResult = TokenTransportResult.builder()
                .body(responseData)
                .cookiesToSet(transportResult != null ? transportResult.getCookiesToSet() : null)
                .cookiesToRemove(transportResult != null ? transportResult.getCookiesToRemove() : null)
                .headers(transportResult != null ? transportResult.getHeaders() : null)
                .build();

        executeDelegateHandler(request, response, finalAuthentication, finalResult);

        if (!response.isCommitted()) {
            onFinalAuthenticationSuccess(request, response, finalAuthentication, finalResult);
        }

        if (!response.isCommitted()) {
            processDefaultResponse(request, response, finalAuthentication, stateType, finalResult);
        }

        if (factorContext != null && factorContext.isCompleted()) {
            publishAuthenticationSuccessEvent(request, finalAuthentication, factorContext, finalResult);
        }
    }

    protected void onFinalAuthenticationSuccess(HttpServletRequest request,
                                                HttpServletResponse response,
                                                Authentication authentication,
                                                TokenTransportResult transportResult) throws IOException {

    }

    private void processDefaultResponse(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication, StateType stateType,
                                        TokenTransportResult result) throws IOException {

        setCookies(response, result);
        if (stateType == StateType.SESSION && !isApiRequest(request)) {
            String targetUrl = determineTargetUrl(request, response);
            response.sendRedirect(targetUrl);
        } else {
            writeJsonResponse(response, result.getBody());
        }
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader != null && acceptHeader.contains("application/json")) {
            return true;
        }
        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("application/json")) {
            return true;
        }
        String requestURI = request.getRequestURI();
        return requestURI != null && requestURI.contains("/api/");
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {

        if (alwaysUse && defaultTargetUrl != null) {
            return request.getContextPath() + defaultTargetUrl;
        }

        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
        if (savedRequest != null) {
            this.requestCache.removeRequest(request, response);
            String redirectUrl = savedRequest.getRedirectUrl();
            if (isValidRedirectUrl(redirectUrl)) {
                return redirectUrl;
            }
        }

        if(defaultTargetUrl != null) return request.getContextPath() + defaultTargetUrl;

        String successUrl = authContextProperties.getUrls().getSingle().getLoginSuccess();
        return request.getContextPath() + successUrl;
    }

    private boolean isValidRedirectUrl(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }
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

    @Override
    protected Map<String, Object> buildResponseData(TokenTransportResult transportResult,
                                                    Authentication authentication,
                                                    HttpServletRequest request,
                                                    HttpServletResponse response) {

        return new HashMap<>();
    }

    private StateType determineStateType(@Nullable FactorContext factorContext) {

        if (factorContext != null && factorContext.getStateConfig() != null) {
            return factorContext.getStateConfig().stateType();
        }

        return authContextProperties.getStateType();
    }

    private Map<String, Object> buildResponseData(
            StateType stateType,
            @Nullable TokenTransportResult transportResult,
            HttpServletRequest request,
            HttpServletResponse response) {

        Map<String, Object> responseData = new HashMap<>();

        if (stateType == StateType.OAUTH2) {
            if (transportResult != null && transportResult.getBody() != null) {
                responseData.putAll(transportResult.getBody());
            }
        }

        responseData.put("authenticated", true);
        responseData.put("status", "MFA_COMPLETED");
        responseData.put("message", "인증이 완료되었습니다.");
        responseData.put("redirectUrl", determineTargetUrl(request, response));
        responseData.put("stateType", stateType.name());

        return responseData;
    }

    private void publishAuthenticationSuccessEvent(HttpServletRequest request,
                                                   Authentication authentication,
                                                   @Nullable FactorContext factorContext,
                                                   TokenTransportResult transportResult) {
        try {
            if (zeroTrustEventPublisher == null) {
                return;
            }

            String userName = authentication.getName();

            Map<String, Object> payload = new HashMap<>();
            payload.put("requestPath", request.getRequestURI());
            payload.put("httpMethod", request.getMethod());
            payload.put("authenticationType", factorContext != null && factorContext.isCompleted() ? "MFA" : "PRIMARY");

            if (factorContext != null) {
                payload.put("mfaCompleted", factorContext.isCompleted());
                payload.put("deviceId", factorContext.getAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID));
                payload.put("mfaMethod", factorContext.getCurrentProcessingFactor() != null ?
                        factorContext.getCurrentProcessingFactor().toString() : null);
            }

            if (transportResult != null && transportResult.getBody() != null) {
                payload.put("authenticationResult", transportResult.getBody().get("status"));
            }

            zeroTrustEventPublisher.publishAuthenticationSuccess(
                    userName,
                    request.getSession(false) != null ? request.getSession().getId() : null,
                    extractClientIp(request),
                    extractUserAgent(request),
                    payload
            );

        } catch (Exception e) {
            log.error("Failed to publish authentication success event", e);
        }
    }

    private String extractUserAgent(HttpServletRequest request) {
        if (hcadProperties != null && hcadProperties.isEnableSimulatedUserAgent()) {
            String simulated = request.getHeader("X-Simulated-User-Agent");
            if (simulated != null && !simulated.isEmpty()) {
                return simulated;
            }
        }
        return request.getHeader("User-Agent");
    }

    protected Map<String, Object> createProgressInfo(int currentStep, int totalSteps) {
        Map<String, Object> progress = new HashMap<>();
        progress.put("current", currentStep);
        progress.put("total", totalSteps);
        progress.put("percentage", (int) Math.round((currentStep / (double) totalSteps) * 100));
        return progress;
    }

    protected Map<String, Object> createFactorDetail(String factorType) {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", factorType);

        switch (factorType.toUpperCase()) {
            case "MFA_OTT":
                detail.put("displayName", "이메일 인증 코드");
                detail.put("icon", "email");
                break;
            case "MFA_PASSKEY":
                detail.put("displayName", "Passkey 생체 인증");
                detail.put("icon", "fingerprint");
                break;
            case "MFA_TOTP":
                detail.put("displayName", "인증 앱 (TOTP)");
                detail.put("icon", "app");
                break;
            case "MFA_SMS":
                detail.put("displayName", "SMS 인증");
                detail.put("icon", "phone");
                break;
            default:
                detail.put("displayName", factorType);
                detail.put("icon", "security");
        }

        return detail;
    }

    protected boolean processErrorEventRecommendation(FactorContext factorContext,
                                                      HttpServletRequest request,
                                                      String sessionId) {
        if (factorContext == null) {
            return false;
        }

        MfaEvent errorEvent = (MfaEvent) factorContext.getAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION);

        if (errorEvent != null) {

            try {
                boolean errorEventSent = stateMachineIntegrator.sendEvent(errorEvent, factorContext, request);

                if (errorEventSent) {

                    factorContext.removeAttribute("errorEventRecommendation");
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

    private void resetActionOnMfaSuccess(String userId, HttpServletRequest request) {
        if (userId == null || userId.isBlank() || actionRedisRepository == null) {
            return;
        }

        try {
            ZeroTrustAction previousAction = actionRedisRepository.getActionFromHash(userId);
            actionRedisRepository.saveActionWithPrevious(userId, ZeroTrustAction.ALLOW);

            boolean isLlmTriggeredMfa = previousAction == ZeroTrustAction.CHALLENGE
                    || previousAction == ZeroTrustAction.ESCALATE;
            if (isLlmTriggeredMfa) {
                learnOnLlmChallengedMfaSuccess(userId, request);
            }

        } catch (Exception e) {
            log.error("[MFA] Failed to set action to ALLOW for user: {}", userId, e);
        }
    }

    private void learnOnLlmChallengedMfaSuccess(String userId, HttpServletRequest request) {
        try {
            SecurityDecision decision = SecurityDecision.builder()
                    .action(ZeroTrustAction.ALLOW)
                    .confidence(0.95)
                    .riskScore(0.05)
                    .reasoning("LLM-challenged MFA completed - verified as normal behavior")
                    .build();

            SecurityEvent event = SecurityEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .source(SecurityEvent.EventSource.IAM)
                    .userId(userId)
                    .sourceIp(extractClientIp(request))
                    .sessionId(request.getSession(false) != null ?
                            request.getSession(false).getId() : null)
                    .userAgent(request.getHeader("User-Agent"))
                    .timestamp(LocalDateTime.now())
                    .description("LLM-challenged MFA success - learning")
                    .build();

            securityLearningService.learnAndStore(userId, decision, event);

        } catch (Exception e) {
            log.error("[MFA] Failed to learn on LLM-challenged MFA success: userId={}", userId, e);
        }
    }
}