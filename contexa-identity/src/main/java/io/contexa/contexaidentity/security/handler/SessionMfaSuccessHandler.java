package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class SessionMfaSuccessHandler extends SessionBasedSuccessHandler {

    public SessionMfaSuccessHandler(AuthResponseWriter responseWriter,
                                    AuthContextProperties authContextProperties) {
        super(responseWriter, authContextProperties);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        onAuthenticationSuccess(request, response, authentication, null);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication,
                                        @Nullable TokenTransportResult tokenTransportResult)
            throws IOException, ServletException {

        if (response.isCommitted()) {
            log.warn("Response already committed for MFA authentication success");
            return;
        }

        String targetUrl = determineTargetUrl(request, response);

        if (isApiRequest(request)) {

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("authenticated", true);
            responseData.put("username", authentication.getName());
            responseData.put("mfaCompleted", true);
            responseData.put("redirectUrl", targetUrl);
            responseData.put("stateType", "SESSION");
            responseData.put("message", "MFA 인증이 완료되었습니다.");

            responseWriter.writeSuccessResponse(response, responseData, HttpServletResponse.SC_OK);

        } else {
            response.sendRedirect(targetUrl);
        }
    }

    @Override
    protected String getDefaultTargetUrl(HttpServletRequest request) {
        return request.getContextPath() + authContextProperties.getUrls().getMfa().getSuccess();
    }
}
