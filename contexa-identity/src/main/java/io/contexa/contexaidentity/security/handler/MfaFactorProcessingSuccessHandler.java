package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.filter.RestAuthenticationToken;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
public final class MfaFactorProcessingSuccessHandler extends AbstractMfaAuthenticationSuccessHandler {

    private final AuthResponseWriter responseWriter;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final AuthUrlProvider authUrlProvider;

    public MfaFactorProcessingSuccessHandler(MfaStateMachineIntegrator mfaStateMachineIntegrator,
                                             AuthResponseWriter responseWriter,
                                             AuthContextProperties authContextProperties,
                                             MfaSessionRepository sessionRepository,
                                             TokenService tokenService,
                                             AuthUrlProvider authUrlProvider,
                                             ZeroTrustEventPublisher zeroTrustEventPublisher,
                                             RedisTemplate<String, Object> redisTemplate,
                                             BaselineLearningService baselineLearningService) {
        super(tokenService, responseWriter, sessionRepository,
              mfaStateMachineIntegrator, authContextProperties,
              zeroTrustEventPublisher, redisTemplate, baselineLearningService);
        this.responseWriter = responseWriter;
        this.stateMachineIntegrator = mfaStateMachineIntegrator;
        this.sessionRepository = sessionRepository;
        this.authUrlProvider = authUrlProvider;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        Authentication converterAuthentication = replaceWithSerializableAuthentication(authentication);
        if (converterAuthentication != null) {
            SecurityContextHolder.getContext().setAuthentication(converterAuthentication);
        }

        FactorContext factorContext = (FactorContext) request.getAttribute("io.contexa.mfa.FactorContext");

        if (factorContext == null) {
            factorContext = stateMachineIntegrator.loadFactorContextFromRequest(request);
        } else {
        }

        String username = getPrincipalUsername(converterAuthentication);
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), username)) {
            handleInvalidContext(response, request, converterAuthentication);
            return;
        }

        if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) {
            log.warn("MFA session {} not found in {} repository during factor processing success",
                    factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
            handleSessionNotFound(response, request, factorContext);
            return;
        }

        boolean eventAccepted = stateMachineIntegrator.sendEvent(MfaEvent.FACTOR_VERIFIED_SUCCESS, factorContext, request);

        if (!eventAccepted) {
            handleStateTransitionError(response, request, factorContext);
            return;
        }

        MfaState currentState = factorContext.getCurrentState();

        if (currentState == MfaState.FACTOR_VERIFICATION_COMPLETED) {

            boolean determined = stateMachineIntegrator.sendEvent(MfaEvent.DETERMINE_NEXT_FACTOR, factorContext, request);

            if (!determined) {
                log.error("Failed to determine next factor for session: {}", factorContext.getMfaSessionId());
                handleStateTransitionError(response, request, factorContext);
                return;
            }

            MfaEvent nextEvent = (MfaEvent) factorContext.getAttribute(FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION);
            if (nextEvent != null) {

                boolean eventSent;
                if (nextEvent == MfaEvent.FACTOR_SELECTED && factorContext.getCurrentProcessingFactor() != null) {

                    Map<String, Object> headers = new HashMap<>();
                    headers.put("selectedFactor", factorContext.getCurrentProcessingFactor().name());
                    eventSent = stateMachineIntegrator.sendEvent(nextEvent, factorContext, request, headers);
                } else if (nextEvent == MfaEvent.INITIATE_CHALLENGE_AUTO) {
                    eventSent = stateMachineIntegrator.sendEvent(nextEvent, factorContext, request);
                } else {
                    eventSent = stateMachineIntegrator.sendEvent(nextEvent, factorContext, request);
                }

                if (!eventSent) {
                    log.error("Failed to send recommended event: {} for session: {}", nextEvent, factorContext.getMfaSessionId());
                    handleStateTransitionError(response, request, factorContext);
                    return;
                }

                factorContext.removeAttribute("nextEventRecommendation");
            }

        }

        currentState = factorContext.getCurrentState();

        if (currentState == MfaState.ALL_FACTORS_COMPLETED || currentState == MfaState.MFA_SUCCESSFUL) {
            handleFinalAuthenticationSuccess(request, response, converterAuthentication, factorContext);

        } else if (currentState == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                factorContext.getCurrentProcessingFactor() != null) {

            AuthType nextFactor = factorContext.getCurrentProcessingFactor();

            String nextUrl = determineNextFactorUrl(nextFactor, request);

            int currentStep = (nextFactor == AuthType.MFA_OTT) ? 2 : 3;
            Map<String, Object> responseBody = createMfaContinueResponse(
                    "다음 인증 단계로 진행합니다: " + nextFactor.name(),
                    factorContext, nextUrl, currentStep);
            responseBody.put("nextFactorType", nextFactor.name());

            if (!response.isCommitted()) {
                responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
            } else {
                log.warn("Response already committed for user: {}, cannot write MFA continue response",
                        factorContext.getUsername());
            }

        } else if (currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION &&
                factorContext.getCurrentProcessingFactor() != null) {

            AuthType nextFactor = factorContext.getCurrentProcessingFactor();

            String nextUrl = determineNextFactorUrl(nextFactor, request);
            int currentStep = (nextFactor == AuthType.MFA_OTT) ? 2 : 3;
            Map<String, Object> responseBody = createMfaContinueResponse(
                    "챌린지가 준비되었습니다: " + nextFactor.name(),
                    factorContext, nextUrl, currentStep);
            responseBody.put("nextFactorType", nextFactor.name());
            responseBody.put("challengeReady", true);

            if (!response.isCommitted()) {
                responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
            }

        } else if (currentState == MfaState.AWAITING_FACTOR_SELECTION) {

            Map<String, Object> responseBody = createMfaContinueResponse(
                    "인증 수단을 선택해주세요.",
                    factorContext,
                    request.getContextPath() + authUrlProvider.getMfaSelectFactor(),
                    2
            );

            java.util.List<Map<String, Object>> factorDetails = factorContext.getAvailableFactors().stream()
                    .map(authType -> createFactorDetail(authType.name()))
                    .toList();
            responseBody.put("availableFactors", factorDetails);

            if (!response.isCommitted()) {
                responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
            } else {
                log.warn("Response already committed for user: {}, cannot write factor selection response",
                        factorContext.getUsername());
            }

        } else {

            log.error("Unexpected state {} after factor verification", currentState);
            handleGenericError(response, request, factorContext,
                    "예상치 못한 상태: " + currentState);
        }
    }

    private Map<String, Object> createMfaContinueResponse(String message, FactorContext factorContext, String nextStepUrl, int currentStep) {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", "MFA_CONTINUE");
        responseBody.put("message", message);
        responseBody.put("authenticated", false);
        responseBody.put("nextStepUrl", nextStepUrl);
        responseBody.put("nextStepId", factorContext.getCurrentStepId());
        responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
        responseBody.put("progress", createProgressInfo(currentStep, 3));

        return responseBody;
    }

    private void handleSessionNotFound(HttpServletResponse response, HttpServletRequest request,
                                       FactorContext factorContext) throws IOException {
        log.warn("Session not found in {} repository during factor processing success: {}",
                sessionRepository.getRepositoryType(), factorContext.getMfaSessionId());

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("mfaSessionId", factorContext.getMfaSessionId());

        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "SESSION_NOT_FOUND", "MFA 세션을 찾을 수 없습니다.", request.getRequestURI(), errorResponse);
        } else {
            log.warn("Response already committed, cannot write SESSION_NOT_FOUND error for session: {}",
                    factorContext.getMfaSessionId());
        }
    }

    private void handleInvalidContext(HttpServletResponse response, HttpServletRequest request,
                                      @Nullable Authentication authentication) throws IOException {
        log.warn("MFA Factor Processing Success using {} repository: Invalid FactorContext. Message: {}. User from auth: {}",
                sessionRepository.getRepositoryType(), "MFA 팩터 처리 성공 후 컨텍스트를 찾을 수 없거나 사용자가 일치하지 않습니다.",
                (authentication != null ? authentication.getName() : "UnknownUser"));

        String oldSessionId = sessionRepository.getSessionId(request);
        if (oldSessionId != null) {
            try {
                stateMachineIntegrator.releaseStateMachine(oldSessionId);
                sessionRepository.removeSession(oldSessionId, request, null);
            } catch (Exception e) {
                log.warn("Failed to release invalid session using {} repository: {}",
                        sessionRepository.getRepositoryType(), oldSessionId, e);
            }
        }

        Map<String, Object> errorResponse = new HashMap<>();

        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "MFA_FACTOR_SUCCESS_NO_CONTEXT",
                    "MFA 세션 컨텍스트 오류: " + "MFA 팩터 처리 성공 후 컨텍스트를 찾을 수 없거나 사용자가 일치하지 않습니다.", request.getRequestURI(), errorResponse);
        } else {
            log.warn("Response already committed, cannot write INVALID_CONTEXT error: {}", "MFA_FACTOR_SUCCESS_NO_CONTEXT");
        }
    }

    private String determineNextFactorUrl(AuthType factorType, HttpServletRequest request) {
        return switch (factorType) {
            case MFA_OTT -> request.getContextPath() +
                    authUrlProvider.getOttRequestCodeUi();
            case MFA_PASSKEY -> request.getContextPath() +
                    authUrlProvider.getPasskeyChallengeUi();
            default -> {
                log.error("Unsupported MFA factor type: {}", factorType);
                yield request.getContextPath() + authUrlProvider.getMfaSelectFactor();
            }
        };
    }

    private void handleStateTransitionError(HttpServletResponse response, HttpServletRequest request,
                                            FactorContext ctx) throws IOException {
        log.error("State Machine transition error for session: {}", ctx.getMfaSessionId());
        stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, ctx, request);

        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "STATE_TRANSITION_ERROR", "상태 전이 오류가 발생했습니다.",
                    request.getRequestURI());
        } else {
            log.warn("Response already committed, cannot write STATE_TRANSITION_ERROR for session: {}",
                    ctx.getMfaSessionId());
        }
    }

    private void handleGenericError(HttpServletResponse response, HttpServletRequest request,
                                    FactorContext ctx, String message) throws IOException {
        log.error("Generic error during MFA factor processing for user {}: {}", ctx.getUsername(), message);

        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "MFA_PROCESSING_ERROR", message, request.getRequestURI());
        } else {
            log.warn("Response already committed, cannot write MFA_PROCESSING_ERROR for user: {}",
                    ctx.getUsername());
        }
        try {
            stateMachineIntegrator.releaseStateMachine(ctx.getMfaSessionId());
        } catch (Exception e) {
            log.warn("Failed to release State Machine session after generic error: {}", ctx.getMfaSessionId(), e);
        }
    }

    private String getPrincipalUsername(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof UnifiedCustomUserDetails customUserDetails) {
            return customUserDetails.getAccount().getUsername();
        } else if (principal instanceof UserDto userDto) {
            return userDto.getUsername();
        } else {
            return principal.toString();
        }
    }

    private Authentication replaceWithSerializableAuthentication(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof ImmutablePublicKeyCredentialUserEntity entity) {
            try {
                UserDto userDto = UserDto.builder()
                        .username(entity.getName())
                        .build();

                java.util.Set<GrantedAuthority> authorities = new java.util.HashSet<>((java.util.Collection<? extends GrantedAuthority>) authentication.getAuthorities());
                return RestAuthenticationToken.authenticated(new UnifiedCustomUserDetails(userDto, authorities), authentication.getAuthorities());

            } catch (Exception e) {
                log.error("Failed to replace Authentication with serializable version. " +
                        "UnifiedCustomUserDetails will remain in SecurityContext (may cause Redis serialization error)", e);
                return null;
            }
        }
        return authentication;
    }
}
