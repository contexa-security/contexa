package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.store.TokenInfo;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * OAuth2 기반 LogoutHandler
 * - Refresh Token 무효화 및 블랙리스트 추가
 * - SecurityContext 초기화
 * - 쿠키 삭제
 * - JSON 응답 작성
 */
public class OAuth2LogoutHandler implements LogoutHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2LogoutHandler.class);
    private final TokenService tokenService;
    private final AuthResponseWriter responseWriter;

    public OAuth2LogoutHandler(TokenService tokenService, AuthResponseWriter responseWriter) {
        this.tokenService = Objects.requireNonNull(tokenService, "tokenService cannot be null");
        this.responseWriter = Objects.requireNonNull(responseWriter, "responseWriter cannot be null");
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String refreshToken = tokenService.resolveRefreshToken(request);
        String username = (authentication != null) ? authentication.getName() : "UNKNOWN_USER_LOGOUT";
        boolean errorOccurred = false;
        String errorMessage = "로그아웃 처리 중 오류 발생"; // 기본 오류 메시지

        try {
            if (refreshToken != null) {
                log.debug("Attempting to invalidate and blacklist refresh token for user: {}", username);
                tokenService.invalidateRefreshToken(refreshToken); // 저장소에서 제거
                tokenService.blacklistRefreshToken(refreshToken, username, TokenInfo.REASON_LOGOUT); // 블랙리스트 추가
                log.info("Successfully invalidated and blacklisted refresh token for user: {}", username);
            } else {
                log.debug("No refresh token found in request for user: {}. Assuming already logged out or token not used.", username);
            }
        } catch (AuthenticationException ex) {
            log.warn("AuthenticationException during logout for user {}: {}", username, ex.getMessage());
            errorOccurred = true;
            errorMessage = "로그아웃 중 인증 오류 발생: " + ex.getMessage();
            // SecurityContextHolder.clearContext()는 finally에서 처리
        } catch (Exception ex) {
            log.error("Unexpected error during refresh token invalidation/blacklisting for user {}: {}", username, ex.getMessage(), ex);
            errorOccurred = true;
            errorMessage = "로그아웃 처리 중 예상치 못한 오류 발생: " + ex.getMessage();
        } finally {
            SecurityContextHolder.clearContext();
            log.debug("SecurityContext cleared for user: {}", username);

            if (!response.isCommitted()) {
                try {
                    TokenTransportResult clearResult = tokenService.prepareClearTokens();
                    if (clearResult.getCookiesToRemove() != null) {
                        for (ResponseCookie cookie : clearResult.getCookiesToRemove()) {
                            response.addHeader("Set-Cookie", cookie.toString());
                        }
                    }
                    if (errorOccurred) {
                        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "LOGOUT_FAILED", errorMessage, request.getRequestURI());
                    } else {
                        Map<String, Object> successBody = clearResult.getBody() != null ?
                                new HashMap<>(clearResult.getBody()) : new HashMap<>();
                        if (!successBody.containsKey("message")) {
                            successBody.put("message", "성공적으로 로그아웃되었습니다.");
                        }
                        successBody.put("status", "LOGGED_OUT");
                        successBody.put("redirectUrl", "/loginForm"); // 예시
                        responseWriter.writeSuccessResponse(response, successBody, HttpServletResponse.SC_OK);
                    }
                } catch (IOException e) {
                    log.error("Error writing logout response for user {}: {}", username, e.getMessage());
                }
            }
        }
    }
}


