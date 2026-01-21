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

        SecurityContext context = SecurityContextHolder.getContext();
        context.setAuthentication(accessTokenAuthentication);

    }

    private OAuth2AccessTokenResponse buildTokenResponse(OAuth2AccessTokenAuthenticationToken authentication) {
        OAuth2AccessToken accessToken = authentication.getAccessToken();
        OAuth2RefreshToken refreshToken = authentication.getRefreshToken();
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();

        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                .withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType())
                .scopes(accessToken.getScopes());

        if (accessToken.getExpiresAt() != null) {
            assert accessToken.getIssuedAt() != null;
            long expiresIn = ChronoUnit.SECONDS.between(
                    accessToken.getIssuedAt(),
                    accessToken.getExpiresAt());
            builder.expiresIn(expiresIn);
        }

        if (refreshToken != null) {
            builder.refreshToken(refreshToken.getTokenValue());
        }

        if (!CollectionUtils.isEmpty(additionalParameters)) {
            builder.additionalParameters(additionalParameters);
        }

        return builder.build();
    }

    private void sendTokenResponse(
            HttpServletResponse response,
            OAuth2AccessTokenResponse tokenResponse) throws IOException {

        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        this.accessTokenResponseConverter.write(tokenResponse, MediaType.APPLICATION_JSON, httpResponse);

            }
}
