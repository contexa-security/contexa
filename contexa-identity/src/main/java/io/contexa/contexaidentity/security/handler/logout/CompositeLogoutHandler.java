package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class CompositeLogoutHandler implements LogoutHandler {

    private final List<LogoutStrategy> strategies;
    private final TokenService tokenService;
    private final AuthResponseWriter responseWriter;

    public CompositeLogoutHandler(
            List<LogoutStrategy> strategies,
            TokenService tokenService,
            AuthResponseWriter responseWriter) {

        Assert.notEmpty(strategies, "strategies cannot be empty");
        Assert.notNull(tokenService, "tokenService cannot be null");
        Assert.notNull(responseWriter, "responseWriter cannot be null");
        this.strategies = strategies;
        this.tokenService = tokenService;
        this.responseWriter = responseWriter;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        boolean errorOccurred = false;
        String errorMessage = null;

        try {
            for (LogoutStrategy strategy : strategies) {
                if (strategy.supports(request, authentication)) {
                    strategy.execute(request, response, authentication);
                }
            }
        } catch (Exception ex) {
            log.error("Error during logout: {}", ex.getMessage(), ex);
            errorOccurred = true;
            errorMessage = ex.getMessage();
        } finally {
            SecurityContextHolder.clearContext();

            if (!response.isCommitted()) {
                writeLogoutResponse(request, response, errorOccurred, errorMessage);
            }
        }
    }

    private void writeLogoutResponse(HttpServletRequest request, HttpServletResponse response,
                                     boolean errorOccurred, String errorMessage) {
        try {
            TokenTransportResult clearResult = tokenService.prepareClearTokens();
            if (clearResult.getCookiesToRemove() != null) {
                for (ResponseCookie cookie : clearResult.getCookiesToRemove()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }

            if (errorOccurred) {
                responseWriter.writeErrorResponse(response,
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "LOGOUT_FAILED", errorMessage, request.getRequestURI());
            } else {
                Map<String, Object> body = new HashMap<>();
                body.put("status", "LOGGED_OUT");
                responseWriter.writeSuccessResponse(response, body, HttpServletResponse.SC_OK);
            }
        } catch (IOException e) {
            log.error("Error writing logout response: {}", e.getMessage());
        }
    }
}
