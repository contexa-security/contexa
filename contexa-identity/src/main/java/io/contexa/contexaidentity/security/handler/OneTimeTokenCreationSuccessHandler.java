package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Slf4j
public final class OneTimeTokenCreationSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

    private final MfaStateMachineIntegrator mfaStateMachineIntegrator;
    private final AuthUrlProvider authUrlProvider;
    private final MfaSessionRepository sessionRepository;

    public OneTimeTokenCreationSuccessHandler(
            MfaStateMachineIntegrator mfaStateMachineIntegrator,
            AuthUrlProvider authUrlProvider,
            MfaSessionRepository sessionRepository) {
        this.mfaStateMachineIntegrator = mfaStateMachineIntegrator;
        this.authUrlProvider = authUrlProvider;
        this.sessionRepository = sessionRepository;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException {

        FactorContext factorContext = mfaStateMachineIntegrator.loadFactorContextFromRequest(request);
        String usernameFromToken = token.getUsername();

        if (factorContext != null &&
                MfaFlowTypeUtils.isMfaFlow(factorContext.getFlowTypeName()) &&
                Objects.equals(factorContext.getUsername(), usernameFromToken) &&
                factorContext.getCurrentProcessingFactor() == AuthType.MFA_OTT) {

            if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) {
                log.warn("MFA session {} not found in {} repository during OTT generation",
                        factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
                handleSessionNotFound(request, response, usernameFromToken);
                return;
            }

            sessionRepository.refreshSession(factorContext.getMfaSessionId());

            log.error("[OTT-RESEND] Before sendEvent: retryCount={}, state={}, sessionId={}",
                    factorContext.getRetryCount(), factorContext.getCurrentState(), factorContext.getMfaSessionId());

            mfaStateMachineIntegrator.sendEvent(MfaEvent.INITIATE_CHALLENGE, factorContext, request);

            log.error("[OTT-RESEND] After sendEvent: retryCount={}, state={}, sessionId={}",
                    factorContext.getRetryCount(), factorContext.getCurrentState(), factorContext.getMfaSessionId());

            String challengeUiUrl = authUrlProvider.getOttChallengeUi();
            if (!StringUtils.hasText(challengeUiUrl)) {
                challengeUiUrl = "/mfa/challenge/ott";
                log.warn("MFA OTT challengeUrl not configured, using default: {}", challengeUiUrl);
            }
            String redirectUrl = request.getContextPath() + challengeUiUrl;
            response.sendRedirect(redirectUrl);
            return;
        }

        if ((factorContext == null || !MfaFlowTypeUtils.isMfaFlow(factorContext.getFlowTypeName()))) {
            String email = URLEncoder.encode(usernameFromToken, StandardCharsets.UTF_8);
            String codeSentUrl = authUrlProvider.getOttCodeSent();
            if (!StringUtils.hasText(codeSentUrl)) {
                codeSentUrl = "/ott/sent";
            }

            String redirectUrl = request.getContextPath() + codeSentUrl +
                    "?email=" + email +
                    "&type=code_sent" +
                    "&flow=ott_single" +
                    "&repository=" + sessionRepository.getRepositoryType();

            response.sendRedirect(redirectUrl);
            return;
        }

        log.error("OTT context mismatch: repository={}, flow={}, contextUser={}, tokenUser={}",
                sessionRepository.getRepositoryType(),
                factorContext.getFlowTypeName(),
                factorContext.getUsername(),
                usernameFromToken);

        String ottRequestUrl = authUrlProvider.getOttRequestCodeUi();
        if (!StringUtils.hasText(ottRequestUrl)) {
            ottRequestUrl = "/mfa/ott/request-code-ui";
        }
        response.sendRedirect(request.getContextPath() + ottRequestUrl + "?error=user_not_found");
    }

    private void handleSessionNotFound(HttpServletRequest request, HttpServletResponse response,
                                       String username) throws IOException {
        log.warn("Session not found in {} repository during OTT generation for user: {}",
                sessionRepository.getRepositoryType(), username);

        String redirectUrl = request.getContextPath() + "/login?error=session_not_found&repository=" +
                sessionRepository.getRepositoryType();
        response.sendRedirect(redirectUrl);
    }
}
