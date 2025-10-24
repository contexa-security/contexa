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

/**
 * OAuth2 기반 Refresh Token 처리 필터
 *
 * <p>클라이언트의 {@code /api/auth/refresh} 요청을 처리하여
 * OAuth2 표준 플로우를 통해 Access Token을 갱신합니다.
 *
 * <h3>처리 흐름</h3>
 * <pre>
 * 1. 클라이언트 → POST /api/auth/refresh (쿠키/헤더에 refresh_token)
 * 2. OAuth2RefreshAuthenticationFilter (이 필터)
 * 3. OAuth2TokenService.refresh()
 * 4. OAuth2AuthorizedClientManager.authorize()
 * 5. RefreshTokenOAuth2AuthorizedClientProvider
 * 6. POST /oauth2/token (서버 내부 HTTP 호출)
 * 7. Spring Authorization Server
 * 8. JSON 응답 반환 (AuthResponseWriter)
 * </pre>
 *
 * <h3>보안 기능</h3>
 * <ul>
 *   <li>RefreshTokenStore를 통한 블랙리스트 검증</li>
 *   <li>토큰 재사용 감지 (Token Reuse Detection)</li>
 *   <li>토큰 회전 (Token Rotation)</li>
 *   <li>실패 시 자동 로그아웃</li>
 * </ul>
 *
 * @since 2025.01 - OAuth2 마이그레이션
 * @see io.contexa.contexaidentity.security.token.service.OAuth2TokenService#refresh(String)
 * @see org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager
 */
@Slf4j
public class OAuth2RefreshAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final String refreshUri;
    private final LogoutHandler logoutHandler;
    private final AuthResponseWriter responseWriter;

    /**
     * OAuth2RefreshAuthenticationFilter 생성자
     *
     * @param tokenService OAuth2TokenService 인스턴스
     * @param logoutHandler 로그아웃 핸들러 (실패 시 사용)
     * @param responseWriter JSON 응답 작성기
     */
    public OAuth2RefreshAuthenticationFilter(TokenService tokenService,
                                              LogoutHandler logoutHandler,
                                              AuthResponseWriter responseWriter) {
        this.tokenService = Objects.requireNonNull(tokenService, "TokenService cannot be null");
        this.logoutHandler = logoutHandler;
        this.responseWriter = Objects.requireNonNull(responseWriter, "AuthResponseWriter cannot be null");

        // Refresh URI 확인
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

        // Refresh URI가 아니거나 POST가 아니면 통과
        if (!refreshUri.equals(request.getRequestURI()) ||
            !HttpMethod.POST.name().equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        log.debug("OAuth2RefreshAuthenticationFilter: Processing POST request for refresh URI: {}", request.getRequestURI());

        // Refresh Token 추출 (쿠키 또는 헤더)
        String refreshTokenFromRequest = tokenService.resolveRefreshToken(request);

        if (StringUtils.hasText(refreshTokenFromRequest)) {
            try {
                log.debug("Attempting to refresh token using OAuth2TokenService");

                // OAuth2TokenService.refresh() 호출
                // 내부적으로 OAuth2AuthorizedClientManager → RefreshTokenOAuth2AuthorizedClientProvider 실행
                TokenService.RefreshResult result = tokenService.refresh(refreshTokenFromRequest);

                // TokenTransportResult 생성 (쿠키 설정 + JSON Body)
                TokenTransportResult transportResult = tokenService.prepareTokensForTransport(
                        result.accessToken(),
                        result.refreshToken());

                // 쿠키 설정
                if (transportResult.getCookiesToSet() != null) {
                    for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                        response.addHeader("Set-Cookie", cookie.toString());
                    }
                }

                // JSON 응답 작성
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
            // 토큰이 없으면 204 No Content 또는 그냥 통과
            // 클라이언트가 로그인 페이지로 리다이렉트하도록 유도
            return;
        }
    }

    /**
     * 실패 처리: SecurityContext 클리어 + 로그아웃 + JSON 에러 응답
     */
    private void handleFailure(HttpServletRequest request, HttpServletResponse response,
                                int status, String errorCode, String errorMessage) throws IOException {

        // SecurityContext 클리어
        SecurityContextHolder.clearContext();

        // 로그아웃 핸들러 실행 (토큰 무효화)
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (logoutHandler != null) {
            try {
                logoutHandler.logout(request, response, auth);
            } catch (Exception logoutEx) {
                log.warn("Exception during logout_handler execution after refresh failure: {}", logoutEx.getMessage());
            }
        }

        // JSON 에러 응답 작성
        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, status, errorCode, errorMessage, request.getRequestURI());
        } else {
            log.warn("Response already committed. Cannot write JSON error for refresh failure. Status: {}, ErrorCode: {}",
                    status, errorCode);
        }
    }
}
