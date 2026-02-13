package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
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
public class OAuth2SingleAuthSuccessHandler extends AbstractTokenBasedSuccessHandler {

    public OAuth2SingleAuthSuccessHandler(TokenService tokenService,
                                          AuthResponseWriter responseWriter,
                                          AuthContextProperties authContextProperties) {
        super(tokenService, responseWriter, authContextProperties);
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

        TokenPair tokenPair = createTokenPair(authentication, null, request, response);
        TokenTransportResult transportResult = prepareTokenTransport(
                tokenPair.getAccessToken(), tokenPair.getRefreshToken());

        Map<String, Object> responseData = buildResponseData(transportResult, authentication, request, response);

        setCookies(response, transportResult);

        if (!isApiRequest(request)) {
            String targetUrl = determineTargetUrl(request, response);
            response.sendRedirect(targetUrl);
        } else {
            writeJsonResponse(response, responseData);
        }
    }

    @Override
    protected Map<String, Object> buildResponseData(TokenTransportResult transportResult,
                                                    Authentication authentication,
                                                    HttpServletRequest request,
                                                    HttpServletResponse response) {

        Map<String, Object> responseData = new HashMap<>();

        if (transportResult != null && transportResult.getBody() != null) {
            responseData.putAll(transportResult.getBody());
        }

        responseData.put("authenticated", true);
        responseData.put("redirectUrl", determineTargetUrl(request, response));
        responseData.put("message", "로그인 성공!");
        responseData.put("username", authentication.getName());

        return responseData;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {

        if (alwaysUse && defaultTargetUrl != null) {
            return request.getContextPath() + defaultTargetUrl;
        }

        if (defaultTargetUrl != null) return request.getContextPath() + defaultTargetUrl;

        String successUrl = authContextProperties.getUrls().getSingle().getLoginSuccess();
        return request.getContextPath() + successUrl;
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader != null && acceptHeader.contains("application/json")) {
            return true;
        }
        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("application/json")) {
            return true;
        }
        String requestURI = request.getRequestURI();
        return requestURI != null && requestURI.contains("/api/");
    }
}
