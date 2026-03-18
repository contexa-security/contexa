package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;
import java.util.Map;

/**
 * LogoutSuccessHandler for OAuth2/REST flows.
 * Writes JSON response {"status":"LOGGED_OUT"} after successful logout.
 */
public class OAuth2LogoutSuccessHandler implements LogoutSuccessHandler {

    private final AuthResponseWriter responseWriter;

    public OAuth2LogoutSuccessHandler(AuthResponseWriter responseWriter) {
        this.responseWriter = responseWriter;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {

        if (response.isCommitted()) {
            return;
        }

        responseWriter.writeSuccessResponse(response, Map.of("status", "LOGGED_OUT"), HttpServletResponse.SC_OK);
    }
}
