/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import io.contexa.contexacommon.enums.TokenTransportType;
import io.contexa.contexaidentity.security.token.service.OAuth2TokenService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Entry point through which a client renews its tokens. The refresh token is read the way the configured
 * transport delivers it (cookie or X-Refresh-Token header), the renewal itself is done by the token
 * service through the Spring Authorization Server refresh_token grant, and the new tokens are returned
 * the way the transport expects them.
 *
 * <p>With the cookie transport the request is protected by the CSRF filter. With the header-cookie
 * transport, whose refresh token cookie is sent by the browser automatically while CSRF protection may
 * be off, the request must declare itself as a script request with the X-Requested-With header, which a
 * cross-site form cannot send.</p>
 */
@Slf4j
public final class OAuth2TokenRefreshFilter extends OncePerRequestFilter {

    private static final String XHR_HEADER = "X-Requested-With";
    private static final String XHR_VALUE = "XMLHttpRequest";

    private final RequestMatcher requestMatcher;
    private final TokenService tokenService;
    private final TokenTransportType transportType;
    private final AuthResponseWriter responseWriter;

    public OAuth2TokenRefreshFilter(String refreshUri, TokenService tokenService,
                                    TokenTransportType transportType, AuthResponseWriter responseWriter) {
        Assert.hasText(refreshUri, "refreshUri cannot be empty");
        Assert.notNull(tokenService, "tokenService cannot be null");
        Assert.notNull(transportType, "transportType cannot be null");
        Assert.notNull(responseWriter, "responseWriter cannot be null");
        this.requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, refreshUri);
        this.tokenService = tokenService;
        this.transportType = transportType;
        this.responseWriter = responseWriter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (transportType == TokenTransportType.HEADER_COOKIE && !XHR_VALUE.equalsIgnoreCase(request.getHeader(XHR_HEADER))) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "REFRESH_REQUEST_REJECTED",
                    "The refresh request must be sent by a script with the X-Requested-With header", request.getRequestURI());
            return;
        }

        String refreshToken = tokenService.resolveRefreshToken(request);
        if (!StringUtils.hasText(refreshToken)) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "REFRESH_TOKEN_MISSING",
                    "No refresh token was presented", request.getRequestURI());
            return;
        }

        TokenService.RefreshResult result;
        try {
            result = tokenService.refresh(refreshToken);
        } catch (OAuth2AuthenticationException ex) {
            writeRefusal(request, response, ex.getError());
            return;
        } catch (OAuth2AuthorizationException ex) {
            writeRefusal(request, response, ex.getError());
            return;
        }

        TokenTransportResult transport = tokenService.prepareTokensForTransport(result.accessToken(), result.refreshToken());
        writeCookies(response, transport.getCookiesToSet());
        if (transport.getHeaders() != null) {
            transport.getHeaders().forEach(response::setHeader);
        }
        Map<String, Object> body = new HashMap<>();
        if (transport.getBody() != null) {
            body.putAll(transport.getBody());
        }
        body.put("refreshed", true);
        responseWriter.writeSuccessResponse(response, body, HttpServletResponse.SC_OK);
    }

    private void writeRefusal(HttpServletRequest request, HttpServletResponse response, OAuth2Error error) throws IOException {
        String code = error != null ? error.getErrorCode() : null;
        if (OAuth2TokenService.MFA_CHALLENGE_REQUIRED_ERROR.equals(code)) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "MFA_CHALLENGE_REQUIRED",
                    "Complete the MFA challenge before renewing the tokens", request.getRequestURI());
            return;
        }
        if (OAuth2ErrorCodes.ACCESS_DENIED.equals(code)) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "REFRESH_DENIED",
                    "Token renewal is not allowed for this account at the moment", request.getRequestURI());
            return;
        }
        if (!OAuth2ErrorCodes.INVALID_GRANT.equals(code) && !OAuth2ErrorCodes.INVALID_TOKEN.equals(code)) {
            log.error("Token refresh failed: {}", error);
        }
        TokenTransportResult clear = tokenService.prepareClearTokens();
        if (clear != null) {
            writeCookies(response, clear.getCookiesToRemove());
        }
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "INVALID_REFRESH_TOKEN",
                "The refresh token is invalid, expired or already used", request.getRequestURI());
    }

    private static void writeCookies(HttpServletResponse response, List<ResponseCookie> cookies) {
        if (cookies == null) {
            return;
        }
        for (ResponseCookie cookie : cookies) {
            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        }
    }
}
