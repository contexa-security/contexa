package io.contexa.contexaidentity.security.exceptionhandling;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.domain.ErrorResponse;
import io.contexa.contexacommon.enums.ErrorCode;
import io.contexa.contexacommon.properties.MfaPageConfig;
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

    
    public MfaAuthenticationEntryPoint(ObjectMapper objectMapper, String loginPageUrl, MfaPageConfig mfaPageConfig) {
        super(loginPageUrl);  
        Assert.notNull(objectMapper, "ObjectMapper cannot be null");
        this.objectMapper = objectMapper;
        this.mfaPageConfig = mfaPageConfig;  
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
            String selectFactorUrl = getSelectFactorPageUrl();
            log.debug("Redirecting to Select Factor page: {}", selectFactorUrl);
            return selectFactorUrl;
        }

        
        if ("ott".equalsIgnoreCase(factorType) || isOttRequestPageRequest(request)) {
            String ottRequestUrl = getOttRequestPageUrl();
            log.debug("Redirecting to OTT Request page: {}", ottRequestUrl);
            return ottRequestUrl;
        }

        
        if ("ott-verify".equalsIgnoreCase(factorType) || isOttVerifyPageRequest(request)) {
            String ottVerifyUrl = getOttVerifyPageUrl();
            log.debug("Redirecting to OTT Verify page: {}", ottVerifyUrl);
            return ottVerifyUrl;
        }

        
        if ("passkey".equalsIgnoreCase(factorType) ||
                "webauthn".equalsIgnoreCase(factorType) ||
                isPasskeyChallengeRequest(request)) {
            String passkeyUrl = getPasskeyChallengePageUrl();
            log.debug("Redirecting to Passkey Challenge page: {}", passkeyUrl);
            return passkeyUrl;
        }

        
        if ("configure".equalsIgnoreCase(factorType) || isConfigurePageRequest(request)) {
            String configureUrl = getConfigurePageUrl();
            log.debug("Redirecting to MFA Configure page: {}", configureUrl);
            return configureUrl;
        }

        
        if ("failure".equalsIgnoreCase(factorType) || isFailurePageRequest(request)) {
            String failureUrl = getFailurePageUrl();
            log.debug("Redirecting to MFA Failure page: {}", failureUrl);
            return failureUrl;
        }

        
        return getLoginFormUrl();  
    }

    

    
    private String getSelectFactorPageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomSelectFactorPage()) {
            return mfaPageConfig.getSelectFactorPageUrl();
        }
        return "/mfa/select-factor";  
    }

    
    private String getOttRequestPageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttRequestPage()) {
            return mfaPageConfig.getOttRequestPageUrl();
        }
        return "/mfa/ott/request-code-ui";  
    }

    
    private String getOttVerifyPageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttVerifyPage()) {
            return mfaPageConfig.getOttVerifyPageUrl();
        }
        return "/mfa/challenge/ott";  
    }

    
    private String getPasskeyChallengePageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomPasskeyPage()) {
            return mfaPageConfig.getPasskeyChallengePageUrl();
        }
        return "/mfa/challenge/passkey";  
    }

    
    private String getConfigurePageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomConfigurePage()) {
            return mfaPageConfig.getConfigurePageUrl();
        }
        return "/mfa/configure";  
    }

    
    private String getFailurePageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomFailurePage()) {
            return mfaPageConfig.getFailurePageUrl();
        }
        return "/mfa/failure";  
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
