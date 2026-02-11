package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.properties.AuthContextProperties;
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

    public SessionSingleAuthSuccessHandler(AuthResponseWriter responseWriter,
                                           AuthContextProperties authContextProperties) {
        super(responseWriter, authContextProperties);
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
            log.warn("Response already committed for user: {}", authentication.getName());
            return;
        }

        String targetUrl = determineTargetUrl(request, response);

        if (isApiRequest(request)) {

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("authenticated", true);
            responseData.put("redirectUrl", targetUrl);
            responseData.put("message", "로그인 성공!");
            responseData.put("username", authentication.getName());
            responseData.put("stateType", "SESSION");

            responseWriter.writeSuccessResponse(response, responseData, HttpServletResponse.SC_OK);
        } else {
            response.sendRedirect(targetUrl);
        }
    }

    @Override
    protected String getDefaultTargetUrl(HttpServletRequest request) {
        if(defaultTargetUrl != null) return request.getContextPath() + defaultTargetUrl;
        return request.getContextPath() + authContextProperties.getUrls().getMfa().getSuccess();
    }
}
