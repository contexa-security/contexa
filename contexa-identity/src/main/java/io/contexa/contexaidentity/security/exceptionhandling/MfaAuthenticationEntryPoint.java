package io.contexa.contexaidentity.security.exceptionhandling;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.domain.ErrorResponse;
import io.contexa.contexacommon.enums.ErrorCode;
import io.contexa.contexacommon.properties.MfaPageConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.WebUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.Assert;

import java.io.IOException;
import java.time.Instant;

@Slf4j
public class MfaAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final MfaPageConfig mfaPageConfig;
    private final AuthUrlProvider authUrlProvider;
    private final MfaFlowUrlRegistry mfaFlowUrlRegistry;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    public MfaAuthenticationEntryPoint(ObjectMapper objectMapper, String loginPageUrl,
                                       MfaPageConfig mfaPageConfig, AuthUrlProvider authUrlProvider,
                                       MfaFlowUrlRegistry mfaFlowUrlRegistry,
                                       MfaStateMachineIntegrator stateMachineIntegrator) {
        super(loginPageUrl);
        Assert.notNull(objectMapper, "ObjectMapper cannot be null");
        this.objectMapper = objectMapper;
        this.mfaPageConfig = mfaPageConfig;
        this.authUrlProvider = authUrlProvider;
        this.mfaFlowUrlRegistry = mfaFlowUrlRegistry;
        this.stateMachineIntegrator = stateMachineIntegrator;
    }

    public MfaAuthenticationEntryPoint(ObjectMapper objectMapper, String loginPageUrl, MfaPageConfig mfaPageConfig) {
        this(objectMapper, loginPageUrl, mfaPageConfig, null, null, null);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        if (WebUtil.isApiOrAjaxRequest(request)) {
            response.setContentType("application/json; charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            ErrorResponse body = new ErrorResponse(
                    Instant.now().toString(),
                    HttpServletResponse.SC_UNAUTHORIZED,
                    ErrorCode.AUTH_FAILED.code(),
                    ErrorCode.AUTH_FAILED.message(),
                    request.getRequestURI()
            );

            objectMapper.writeValue(response.getOutputStream(), body);
            return;
        }

        super.commence(request, response, authException);
    }

    @Override
    protected String determineUrlToUseForThisRequest(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) {

        String factorType = request.getParameter("factor.type");

        if ("select".equalsIgnoreCase(factorType) || isSelectFactorRequest(request)) {
            return getSelectFactorPageUrl(request);
        }

        if ("ott".equalsIgnoreCase(factorType) || isOttRequestPageRequest(request)) {
            return getOttRequestPageUrl(request);
        }

        if ("ott-verify".equalsIgnoreCase(factorType) || isOttVerifyPageRequest(request)) {
            return getOttVerifyPageUrl(request);
        }

        if ("passkey".equalsIgnoreCase(factorType) || "webauthn".equalsIgnoreCase(factorType) ||
                isPasskeyChallengeRequest(request)) {
            return getPasskeyChallengePageUrl(request);
        }

        if ("configure".equalsIgnoreCase(factorType) || isConfigurePageRequest(request)) {
            return getConfigurePageUrl(request);
        }

        if ("failure".equalsIgnoreCase(factorType) || isFailurePageRequest(request)) {
            return getFailurePageUrl(request);
        }

        return getLoginFormUrl();  
    }

    private String getSelectFactorPageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomSelectFactorPage()) {
            return mfaPageConfig.getSelectFactorPageUrl();
        }
        return resolveProvider(request).getMfaSelectFactor();
    }

    private String getOttRequestPageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttRequestPage()) {
            return mfaPageConfig.getOttRequestPageUrl();
        }
        return resolveProvider(request).getOttRequestCodeUi();
    }

    private String getOttVerifyPageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttVerifyPage()) {
            return mfaPageConfig.getOttVerifyPageUrl();
        }
        return resolveProvider(request).getOttChallengeUi();
    }

    private String getPasskeyChallengePageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomPasskeyPage()) {
            return mfaPageConfig.getPasskeyChallengePageUrl();
        }
        return resolveProvider(request).getPasskeyChallengeUi();
    }

    private String getConfigurePageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomConfigurePage()) {
            return mfaPageConfig.getConfigurePageUrl();
        }
        return resolveProvider(request).getMfaConfig();
    }

    private String getFailurePageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomFailurePage()) {
            return mfaPageConfig.getFailurePageUrl();
        }
        return resolveProvider(request).getMfaFailure();
    }

    private AuthUrlProvider resolveProvider(HttpServletRequest request) {
        if (stateMachineIntegrator != null) {
            FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
            if (ctx != null && ctx.getFlowTypeName() != null && mfaFlowUrlRegistry != null) {
                AuthUrlProvider flowProvider = mfaFlowUrlRegistry.getProvider(ctx.getFlowTypeName());
                if (flowProvider != null) {
                    return flowProvider;
                }
            }
        }
        if (authUrlProvider != null) {
            return authUrlProvider;
        }
        // Last resort: create minimal provider from ApplicationContext if available
        throw new IllegalStateException("AuthUrlProvider is not available in MfaAuthenticationEntryPoint");
    }

    private boolean isSelectFactorRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/mfa/select-factor") ||
                uri.contains("/select-factor");
    }

    private boolean isOttRequestPageRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/loginOtt") ||
                uri.contains("/ott/request") ||
                uri.contains("/mfa/ott/request");
    }

    private boolean isOttVerifyPageRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/ott/verify") ||
                uri.contains("/challenge/ott") ||
                uri.contains("/mfa/challenge/ott");
    }

    private boolean isPasskeyChallengeRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/loginPasskey") ||
                uri.contains("/webauthn/") ||
                uri.contains("/passkey") ||
                uri.contains("/challenge/passkey");
    }

    private boolean isConfigurePageRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/mfa/configure") ||
                uri.contains("/configure");
    }

    private boolean isFailurePageRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/mfa/failure") ||
                uri.contains("/failure");
    }
}
