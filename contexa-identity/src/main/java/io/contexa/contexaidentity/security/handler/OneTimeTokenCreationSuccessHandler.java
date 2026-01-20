package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
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
        log.info("OneTimeTokenCreationSuccessHandler: Token generated for user '{}' using {} repository",
                token.getUsername(), sessionRepository.getRepositoryType());

        
        FactorContext factorContext = mfaStateMachineIntegrator.loadFactorContextFromRequest(request);
        String usernameFromToken = token.getUsername();

        
        if (factorContext != null &&
                AuthType.MFA.name().equalsIgnoreCase(factorContext.getFlowTypeName()) &&
                Objects.equals(factorContext.getUsername(), usernameFromToken) &&
                factorContext.getCurrentProcessingFactor() == AuthType.OTT) {

            
            if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) {
                log.warn("MFA session {} not found in {} repository during OTT generation",
                        factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
                handleSessionNotFound(request, response, usernameFromToken);
                return;
            }

            log.debug("MFA OTT code generation successful for user: {}. Session ID: {} using {} repository",
                    factorContext.getUsername(), factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());

            
            factorContext.setAttribute(FactorContextAttributes.Timestamps.CHALLENGE_INITIATED_AT,
                                     System.currentTimeMillis());

            
            sessionRepository.refreshSession(factorContext.getMfaSessionId());

            mfaStateMachineIntegrator.saveFactorContext(factorContext);

            String challengeUiUrl = authUrlProvider.getOttChallengeUi();
            if (!StringUtils.hasText(challengeUiUrl)) {
                challengeUiUrl = "/mfa/challenge/ott";
                log.warn("MFA OTT challengeUrl not configured, using default: {}", challengeUiUrl);
            }
            String redirectUrl = request.getContextPath() + challengeUiUrl;
            log.info("Redirecting to MFA OTT challenge page: {} using {} repository",
                    redirectUrl, sessionRepository.getRepositoryType());
            response.sendRedirect(redirectUrl);
            return;
        }

        
        if ((factorContext == null || !AuthType.MFA.name().equalsIgnoreCase(factorContext.getFlowTypeName()))) {
            log.info("Single OTT token generated for user {} using {} repository. Redirecting to 'ott/sent' page.",
                    usernameFromToken, sessionRepository.getRepositoryType());
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

        
        log.warn("OneTimeTokenCreationSuccessHandler: Unhandled scenario or context mismatch using {} repository. " +
                        "FactorContext flow: {}, FactorContext user: {}, Token user: {}. Redirecting to loginForm.",
                sessionRepository.getRepositoryType(),
                factorContext.getFlowTypeName(),
                factorContext.getUsername(),
                usernameFromToken);
        response.sendRedirect(request.getContextPath() + "/loginForm?message=ott_setup_issue&repository=" +
                sessionRepository.getRepositoryType());
    }

    
    private void handleSessionNotFound(HttpServletRequest request, HttpServletResponse response,
                                       String username) throws IOException {
        log.warn("Session not found in {} repository during OTT generation for user: {}",
                sessionRepository.getRepositoryType(), username);

        String redirectUrl = request.getContextPath() + "/loginForm?error=session_not_found&repository=" +
                sessionRepository.getRepositoryType();
        response.sendRedirect(redirectUrl);
    }
}
