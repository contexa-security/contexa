package io.contexa.demo.identity.service.engine;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.demo.identity.dto.AuthenticationProgress;
import io.contexa.demo.identity.service.AuthenticationView;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.net.URI;

@Component
@Profile("contexa")
public class ContexaAuthenticationView implements AuthenticationView {

    private final AuthUrlProvider defaultUrls;
    private final MfaSessionRepository sessions;
    private final MfaStateMachineService states;
    private final ObjectProvider<MfaFlowUrlRegistry> urls;

    public ContexaAuthenticationView(AuthUrlProvider defaultUrls, MfaSessionRepository sessions,
            MfaStateMachineService states, ObjectProvider<MfaFlowUrlRegistry> urls) {
        this.defaultUrls = defaultUrls;
        this.sessions = sessions;
        this.states = states;
        this.urls = urls;
    }

    public String loginUrl(HttpServletRequest request) {
        return request.getContextPath() + defaultUrls.getSingleFormLoginPage();
    }

    public AuthenticationProgress inspect(Authentication authentication, HttpServletRequest request) {
        try {
            String id = sessions.getSessionId(request);
            var factor = id == null ? null : states.getFactorContext(id);
            if (factor != null) {
                return new AuthenticationProgress(
                        factor.getCurrentState().isTerminal() ? "MFA_FLOW_FINISHED" : "MFA_FLOW_ACTIVE",
                        factor.getCurrentState().name(),
                        factor.getCurrentProcessingFactor() == null ? null : factor.getCurrentProcessingFactor().name(),
                        resumeUrl(factor, request));
            }
            return new AuthenticationProgress(authentication == null ? "NOT_AUTHENTICATED" : "NO_ACTIVE_MFA", null,
                    null, null);
        } catch (RuntimeException unavailable) {
            return new AuthenticationProgress("UNAVAILABLE", null, null, null);
        }
    }

    private String resumeUrl(FactorContext context, HttpServletRequest request) {
        var registry = urls.getIfUnique();
        var provider = registry == null ? null : registry.getProvider(context.getFlowTypeName());
        if (provider == null) {
            return null;
        }
        String path = null;
        if (context.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
            path = provider.getMfaSelectFactor();
        } else if (context.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION
                && context.getCurrentProcessingFactor() != null) {
            path = switch (context.getCurrentProcessingFactor()) {
                case MFA_PASSKEY, PASSKEY -> provider.getPasskeyChallengeUi();
                case MFA_OTT, OTT -> provider.getOttChallengeUi();
                default -> null;
            };
        }
        if (path == null) {
            return null;
        }
        URI uri = URI.create(path);
        if (uri.isAbsolute() || uri.getRawAuthority() != null || !path.startsWith("/") || path.startsWith("//")) {
            return null;
        }
        return request.getContextPath() + path;
    }
}
