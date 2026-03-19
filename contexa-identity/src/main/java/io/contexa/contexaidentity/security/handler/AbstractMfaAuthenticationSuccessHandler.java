package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustAccessControlFilter;
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
    private final ZeroTrustEventPublisher zeroTrustEventPublisher;
    private final ZeroTrustActionRepository actionRedisRepository;
    private final SecurityLearningService securityLearningService;
    private final ApplicationContext applicationContext;
    private final AuthUrlProvider authUrlProvider;
    private final MfaFlowUrlRegistry mfaFlowUrlRegistry;
    private final IBlockedUserRecorder blockedUserRecorder;
    private final BlockMfaStateStore blockMfaStateStore;
    private final CentralAuditFacade centralAuditFacade;

    protected AbstractMfaAuthenticationSuccessHandler(TokenService tokenService,
                                                      AuthResponseWriter responseWriter,
                                                      MfaSessionRepository sessionRepository,
                                                      MfaStateMachineIntegrator stateMachineIntegrator,
                                                      AuthContextProperties authContextProperties,
                                                      ZeroTrustEventPublisher zeroTrustEventPublisher,
                                                      ZeroTrustActionRepository actionRedisRepository,
                                                      SecurityLearningService securityLearningService,
                                                      ApplicationContext applicationContext,
                                                      AuthUrlProvider authUrlProvider,
                                                      MfaFlowUrlRegistry mfaFlowUrlRegistry,
                                                      IBlockedUserRecorder blockedUserRecorder,
                                                      BlockMfaStateStore blockMfaStateStore,
                                                      CentralAuditFacade centralAuditFacade) {
        super(tokenService, responseWriter, authContextProperties);
        this.sessionRepository = sessionRepository;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
        this.actionRedisRepository = actionRedisRepository;
        this.securityLearningService = securityLearningService;
        this.applicationContext = applicationContext;
        this.authUrlProvider = authUrlProvider;
        this.mfaFlowUrlRegistry = mfaFlowUrlRegistry;
        this.blockedUserRecorder = blockedUserRecorder;
        this.blockMfaStateStore = blockMfaStateStore;
        this.centralAuditFacade = centralAuditFacade;
    }

    protected final void handleFinalAuthenticationSuccess(HttpServletRequest request,
                                                          HttpServletResponse response,
                                                          Authentication finalAuthentication,
                                                          @Nullable FactorContext factorContext) throws IOException {

        if (response.isCommitted()) {
            log.error("Response already committed for user: {}", finalAuthentication.getName());
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
            Boolean blockMfaFlow = (Boolean) factorContext.getAttribute(ZeroTrustAccessControlFilter.BLOCK_MFA_FLOW_ATTRIBUTE);
            if (Boolean.TRUE.equals(blockMfaFlow)) {
                handleBlockMfaSuccess(userId, request, response);
                return;
            }
            markMfaVerifiedOnChallengeSuccess(userId);
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
            processDefaultResponse(request, response, stateType, finalResult);
        }

        if (factorContext != null && factorContext.isCompleted()) {
            auditAuthenticationSuccess(request, finalAuthentication, factorContext);
        }
    }

    private boolean isIsLlmTriggeredMfa(String userId) {
        ZeroTrustAction currentAction = actionRedisRepository.getActionFromHash(userId);
        return currentAction == ZeroTrustAction.CHALLENGE
                || currentAction == ZeroTrustAction.ESCALATE;
    }

    protected void onFinalAuthenticationSuccess(HttpServletRequest request,
                                                HttpServletResponse response,
                                                Authentication authentication,
                                                TokenTransportResult transportResult) throws IOException {

    }

    private void processDefaultResponse(HttpServletRequest request, HttpServletResponse response, StateType stateType,
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

        String dslDefaultSuccessUrl = getDslDefaultSuccessUrl(request);
        boolean alwaysUseDslUrl = isDslAlwaysUseDefaultSuccessUrl(request);

        if (alwaysUseDslUrl && dslDefaultSuccessUrl != null) {
            return request.getContextPath() + dslDefaultSuccessUrl;
        }

        RequestCache requestCache = new HttpSessionRequestCache();
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            requestCache.removeRequest(request, response);
            String redirectUrl = savedRequest.getRedirectUrl();
            if (isValidRedirectUrl(redirectUrl)) {
                return redirectUrl;
            }
        }

        if (dslDefaultSuccessUrl != null) {
            return request.getContextPath() + dslDefaultSuccessUrl;
        }
        return request.getContextPath() + resolveProvider(request).getMfaSuccess();
    }

    private String getDslDefaultSuccessUrl(HttpServletRequest request) {
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            AuthenticationFlowConfig mfaFlow = findCurrentMfaFlow(platformConfig, request);

            if (mfaFlow != null && mfaFlow.getPrimaryAuthenticationOptions() != null) {
                var formOptions = mfaFlow.getPrimaryAuthenticationOptions().getFormOptions();
                if (formOptions != null) {
                    return formOptions.getDefaultSuccessUrl();
                }
            }
        } catch (Exception e) {
            log.error("Failed to get DSL defaultSuccessUrl: {}", e.getMessage());
        }
        return null;
    }

    private boolean isDslAlwaysUseDefaultSuccessUrl(HttpServletRequest request) {
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            AuthenticationFlowConfig mfaFlow = findCurrentMfaFlow(platformConfig, request);

            if (mfaFlow != null && mfaFlow.getPrimaryAuthenticationOptions() != null) {
                var formOptions = mfaFlow.getPrimaryAuthenticationOptions().getFormOptions();
                if (formOptions != null) {
                    return formOptions.isAlwaysUseDefaultSuccessUrl();
                }
            }
        } catch (Exception e) {
            log.error("Failed to get DSL alwaysUseDefaultSuccessUrl: {}", e.getMessage());
        }
        return false;
    }

    private AuthenticationFlowConfig findCurrentMfaFlow(PlatformConfig platformConfig, HttpServletRequest request) {
        FactorContext ctx = (FactorContext) request.getAttribute("io.contexa.mfa.FactorContext");
        if (ctx == null) {
            ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        }
        if (ctx != null && ctx.getFlowTypeName() != null) {
            String targetFlowTypeName = ctx.getFlowTypeName();
            AuthenticationFlowConfig specificFlow = platformConfig.getFlows().stream()
                    .filter(f -> f.getTypeName().equalsIgnoreCase(targetFlowTypeName))
                    .findFirst()
                    .orElse(null);
            if (specificFlow != null) {
                return specificFlow;
            }
        }
        // Fallback for single MFA flow backward compatibility
        log.error("findCurrentMfaFlow: flowTypeName not available from FactorContext, falling back to first MFA flow");
        return platformConfig.getFlows().stream()
                .filter(f -> MfaFlowTypeUtils.isMfaFlow(f.getTypeName()))
                .findFirst()
                .orElse(null);
    }

    private boolean isValidRedirectUrl(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }

        // Reject absolute URLs to prevent open redirect attacks
        if (url.startsWith("http://") || url.startsWith("https://") || url.startsWith("//")) {
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
        responseData.put("message", "Authentication completed.");
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

            // MFA success resets action to ALLOW (resetActionOnMfaSuccess called before this)
            payload.put("action", ZeroTrustAction.ALLOW.name());

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

    private void auditAuthenticationSuccess(HttpServletRequest request,
                                               Authentication authentication,
                                               @Nullable FactorContext factorContext) {
        if (centralAuditFacade == null) {
            return;
        }
        try {
            String authType = (factorContext != null && factorContext.isCompleted()) ? "MFA" : "PRIMARY";

            Map<String, Object> details = new HashMap<>();
            details.put("authenticationType", authType);
            if (factorContext != null && factorContext.getCurrentProcessingFactor() != null) {
                details.put("mfaMethod", factorContext.getCurrentProcessingFactor().toString());
            }

            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.AUTHENTICATION_SUCCESS)
                    .principalName(authentication.getName())
                    .resourceIdentifier(authentication.getName())
                    .eventSource("IDENTITY")
                    .clientIp(extractClientIp(request))
                    .sessionId(request.getSession(false) != null ? request.getSession(false).getId() : null)
                    .userAgent(request.getHeader("User-Agent"))
                    .resourceUri(request.getRequestURI())
                    .requestUri(request.getRequestURI())
                    .httpMethod(request.getMethod())
                    .action("AUTHENTICATION")
                    .decision("ALLOW")
                    .outcome("SUCCESS")
                    .reason("Authentication completed: " + authType)
                    .details(details)
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit authentication success", e);
        }
    }

    private String extractUserAgent(HttpServletRequest request) {
        return request.getHeader("User-Agent");
    }

    private AuthUrlProvider resolveProvider(HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        if (ctx != null && ctx.getFlowTypeName() != null && mfaFlowUrlRegistry != null) {
            AuthUrlProvider flowProvider = mfaFlowUrlRegistry.getProvider(ctx.getFlowTypeName());
            if (flowProvider != null) {
                return flowProvider;
            }
        }
        return authUrlProvider;
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
                detail.put("displayName", "Email Verification Code");
                detail.put("icon", "email");
                break;
            case "MFA_PASSKEY":
                detail.put("displayName", "Passkey Biometric Authentication");
                detail.put("icon", "fingerprint");
                break;
            case "MFA_TOTP":
                detail.put("displayName", "Authenticator App (TOTP)");
                detail.put("icon", "app");
                break;
            case "MFA_SMS":
                detail.put("displayName", "SMS Verification");
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

    private void handleBlockMfaSuccess(String userId, HttpServletRequest request,
                                         HttpServletResponse response) throws IOException {
        try {
            if (blockedUserRecorder != null) {
                blockedUserRecorder.markMfaVerified(userId);
            }

            if (blockMfaStateStore != null) {
                blockMfaStateStore.setVerified(userId);
                blockMfaStateStore.clearPending(userId);
            }
        } catch (Exception e) {
            log.error("[MFA] Failed to process block MFA success for user: {}", userId, e);
        }

        String redirectUrl = request.getContextPath() + "/zero-trust/blocked";

        if (isApiRequest(request)) {
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("authenticated", true);
            responseData.put("status", "BLOCK_MFA_VERIFIED");
            responseData.put("redirectUrl", redirectUrl);
            writeJsonResponse(response, responseData);
        } else {
            response.sendRedirect(redirectUrl);
        }
    }

    private void markMfaVerifiedOnChallengeSuccess(String userId) {
        try {
            // CHALLENGE MFA -> hcadDataStore only (for LLM prompt MfaVerified flag)
            // blockMfaStateStore is reserved for BLOCK MFA flow only (handleBlockMfaSuccess)
            HCADDataStore hcadDataStore = applicationContext.getBean(HCADDataStore.class);
            if (hcadDataStore != null) {
                hcadDataStore.markMfaVerified(userId);
            }
        } catch (Exception e) {
            log.error("[MFA] Failed to mark MFA verified on challenge success: userId={}", userId, e);
        }
    }

    private void resetActionOnMfaSuccess(String userId, HttpServletRequest request) {
        if (userId == null || userId.isBlank() || actionRedisRepository == null) {
            return;
        }

        try {
            boolean isLlmTriggeredMfa = isIsLlmTriggeredMfa(userId);
            if (isLlmTriggeredMfa) {
                String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
                actionRedisRepository.saveActionWithPrevious(userId, ZeroTrustAction.ALLOW, contextBindingHash);
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
                    .analysisTime(System.currentTimeMillis())
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