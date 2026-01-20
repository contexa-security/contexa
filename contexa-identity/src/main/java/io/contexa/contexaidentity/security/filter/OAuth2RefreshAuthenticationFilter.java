package io.contexa.contexaidentity.security.filter;

import io.contexa.contexaidentity.security.exception.TokenInvalidException;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;


@Slf4j
public class OAuth2RefreshAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final String refreshUri;
    private final LogoutHandler logoutHandler;
    private final AuthResponseWriter responseWriter;

    
    public OAuth2RefreshAuthenticationFilter(TokenService tokenService,
                                              LogoutHandler logoutHandler,
                                              AuthResponseWriter responseWriter) {
        this.tokenService = Objects.requireNonNull(tokenService, "TokenService cannot be null");
        this.logoutHandler = logoutHandler;
        this.responseWriter = Objects.requireNonNull(responseWriter, "AuthResponseWriter cannot be null");

        
        if (tokenService.properties() == null ||
            tokenService.properties().getInternal() == null ||
            !StringUtils.hasText(tokenService.properties().getInternal().getRefreshUri())) {
            throw new IllegalArgumentException("Refresh URI cannot be determined from tokenService properties.");
        }

        this.refreshUri = tokenService.properties().getInternal().getRefreshUri();
        log.info("OAuth2RefreshAuthenticationFilter initialized with refreshUri: {}", refreshUri);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        
        if (!refreshUri.equals(request.getRequestURI()) ||
            !HttpMethod.POST.name().equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        log.debug("OAuth2RefreshAuthenticationFilter: Processing POST request for refresh URI: {}", request.getRequestURI());

        
        String refreshTokenFromRequest = tokenService.resolveRefreshToken(request);

        if (StringUtils.hasText(refreshTokenFromRequest)) {
            try {
                log.debug("Attempting to refresh token using OAuth2TokenService");

                
                
                TokenService.RefreshResult result = tokenService.refresh(refreshTokenFromRequest);

                
                TokenTransportResult transportResult = tokenService.prepareTokensForTransport(
                        result.accessToken(),
                        result.refreshToken());

                
                if (transportResult.getCookiesToSet() != null) {
                    for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                        response.addHeader("Set-Cookie", cookie.toString());
                    }
                }

                
                responseWriter.writeSuccessResponse(response, transportResult.getBody(), HttpServletResponse.SC_OK);

                log.info("OAuth2 token refreshed successfully. Response generated and sent.");
                return;

            } catch (TokenInvalidException tie) {
                log.warn("Invalid refresh token for {}: {}", request.getRequestURI(), tie.getMessage());
                handleFailure(request, response, HttpServletResponse.SC_UNAUTHORIZED,
                        "invalid_refresh_token",
                        "리프레시 토큰이 유효하지 않거나 만료되었습니다: " + tie.getMessage());
                return;

            } catch (Exception e) {
                log.error("Unexpected error during OAuth2 token refresh for {}: {}",
                        request.getRequestURI(), e.getMessage(), e);
                handleFailure(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "token_refresh_error",
                        "토큰 리프레시 중 서버 오류가 발생했습니다.");
                return;
            }
        } else {
            log.warn("No refresh token found in POST request to {}", refreshUri);
            
            
            return;
        }
    }

    
    private void handleFailure(HttpServletRequest request, HttpServletResponse response,
                                int status, String errorCode, String errorMessage) throws IOException {

        
        SecurityContextHolder.clearContext();

        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (logoutHandler != null) {
            try {
                logoutHandler.logout(request, response, auth);
            } catch (Exception logoutEx) {
                log.warn("Exception during logout_handler execution after refresh failure: {}", logoutEx.getMessage());
            }
        }

        
        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, status, errorCode, errorMessage, request.getRequestURI());
        } else {
            log.warn("Response already committed. Cannot write JSON error for refresh failure. Status: {}, ErrorCode: {}",
                    status, errorCode);
        }
    }
}
