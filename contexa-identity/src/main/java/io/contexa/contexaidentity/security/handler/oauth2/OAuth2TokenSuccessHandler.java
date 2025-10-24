package io.contexa.contexaidentity.security.handler.oauth2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.Map;

/**
 * OAuth2 토큰 엔드포인트 성공 핸들러
 *
 * <p>OAuth2TokenEndpointFilter의 성공 핸들러로 사용됩니다.
 * 내부 호출과 외부 호출을 구분하여 처리합니다:
 *
 * <h3>내부 호출 (OAuth2TokenResponseHolder.isInternalCall() == true)</h3>
 * <ul>
 *   <li>HTTP 응답을 직접 쓰지 않음</li>
 *   <li>ThreadLocal에 OAuth2AccessTokenResponse 저장</li>
 *   <li>호출자가 ThreadLocal 에서 응답 추출</li>
 * </ul>
 *
 * <h3>외부 호출 (기본)</h3>
 * <ul>
 *   <li>Spring Security 표준 방식으로 HTTP 응답 작성</li>
 *   <li>OAuth2AccessTokenResponseHttpMessageConverter 사용</li>
 *   <li>JSON 형식으로 토큰 응답 전송</li>
 * </ul>
 *
 * <h3>OAuth2StateConfigurer 연동</h3>
 * <pre>
 * // OAuth2StateConfigurer.java (139-159줄)
 * authzServer.tokenEndpoint(tokenEndpoint -> {
 *     AuthenticationSuccessHandler successHandler =
 *         context.getBean("oauth2TokenSuccessHandler", AuthenticationSuccessHandler.class);
 *     tokenEndpoint.accessTokenResponseHandler(successHandler);
 * });
 * </pre>
 *
 * @since 2025.01
 * @see io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateConfigurer
 */
@Slf4j
public class OAuth2TokenSuccessHandler implements AuthenticationSuccessHandler {

    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
                (OAuth2AccessTokenAuthenticationToken) authentication;

        // 항상 SecurityContext에 OAuth2AccessTokenAuthenticationToken 저장
        // (내부 호출에서 SecurityContext로 추출하기 위함)
        SecurityContext context = SecurityContextHolder.getContext();
        context.setAuthentication(accessTokenAuthentication);

        // HTTP 응답이 이미 커밋되지 않은 경우에만 응답 작성
      /*  if (!response.isCommitted()) {
            log.debug("Writing OAuth2 token response to HTTP");
            OAuth2AccessTokenResponse tokenResponse = buildTokenResponse(accessTokenAuthentication);
            sendTokenResponse(response, tokenResponse);
        } else {
            log.debug("Response already committed - skipping HTTP response write");
        }*/
    }

    /**
     * OAuth2AccessTokenAuthenticationToken → OAuth2AccessTokenResponse 변환
     *
     * @param authentication OAuth2AccessTokenAuthenticationToken
     * @return OAuth2AccessTokenResponse
     */
    private OAuth2AccessTokenResponse buildTokenResponse(OAuth2AccessTokenAuthenticationToken authentication) {
        OAuth2AccessToken accessToken = authentication.getAccessToken();
        OAuth2RefreshToken refreshToken = authentication.getRefreshToken();
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();

        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                .withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType())
                .scopes(accessToken.getScopes());

        // expiresIn 계산
        if (accessToken.getExpiresAt() != null) {
            assert accessToken.getIssuedAt() != null;
            long expiresIn = ChronoUnit.SECONDS.between(
                    accessToken.getIssuedAt(),
                    accessToken.getExpiresAt());
            builder.expiresIn(expiresIn);
        }

        // Refresh Token 추가
        if (refreshToken != null) {
            builder.refreshToken(refreshToken.getTokenValue());
        }

        // Additional Parameters 추가
        if (!CollectionUtils.isEmpty(additionalParameters)) {
            builder.additionalParameters(additionalParameters);
        }

        return builder.build();
    }

    /**
     * HTTP 응답으로 OAuth2 토큰 전송
     *
     * @param response HttpServletResponse
     * @param tokenResponse OAuth2AccessTokenResponse
     * @throws IOException 응답 작성 실패 시
     */
    private void sendTokenResponse(
            HttpServletResponse response,
            OAuth2AccessTokenResponse tokenResponse) throws IOException {

        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        this.accessTokenResponseConverter.write(tokenResponse, MediaType.APPLICATION_JSON, httpResponse);

        log.debug("OAuth2 token response sent successfully");
    }
}
