package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class SessionSingleAuthSuccessHandler extends SessionBasedSuccessHandler {

    private final LoginPolicyHandler loginPolicyHandler;

    public SessionSingleAuthSuccessHandler(AuthResponseWriter responseWriter,
                                           AuthContextProperties authContextProperties,
                                           @Nullable LoginPolicyHandler loginPolicyHandler) {
        super(responseWriter, authContextProperties);
        this.loginPolicyHandler = loginPolicyHandler;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        onAuthenticationSuccess(request, response, authentication, null);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication,
                                        @Nullable TokenTransportResult providedResult) throws IOException {

        if (response.isCommitted()) {
            log.error("Response already committed for user: {}", authentication.getName());
            return;
        }

        if (loginPolicyHandler != null) {
            try {
                loginPolicyHandler.onLoginSuccess(authentication.getName(), request.getRemoteAddr());
            } catch (Exception e) {
                log.error("Failed to record login success for user: {}", authentication.getName(), e);
            }
        }

        String targetUrl = determineTargetUrl(request, response);

        if (isApiRequest(request)) {

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("authenticated", true);
            responseData.put("redirectUrl", targetUrl);
            responseData.put("message", "Login successful!");
            responseData.put("username", authentication.getName());
            responseData.put("stateType", "SESSION");

            responseWriter.writeSuccessResponse(response, responseData, HttpServletResponse.SC_OK);
        } else {
            response.sendRedirect(targetUrl);
        }
    }

    @Override
    protected String getDefaultTargetUrl(HttpServletRequest request) {

        if (alwaysUse && defaultTargetUrl != null) {
            return request.getContextPath() + defaultTargetUrl;
        }

        if (defaultTargetUrl != null) return request.getContextPath() + defaultTargetUrl;

        String successUrl = authContextProperties.getUrls().getSingle().getLoginSuccess();
        return request.getContextPath() + successUrl;
    }
}
