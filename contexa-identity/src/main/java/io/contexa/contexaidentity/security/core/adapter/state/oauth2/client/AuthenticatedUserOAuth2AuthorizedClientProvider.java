package io.contexa.contexaidentity.security.core.adapter.state.oauth2.client;

import io.contexa.contexaidentity.domain.dto.UserDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

/**
 * Authenticated User Grant Type을 지원하는 OAuth2AuthorizedClientProvider
 *
 * <p>이미 인증된 사용자의 정보를 기반으로 Authorization Server로부터
 * OAuth2 Access Token을 획득합니다.
 *
 * <h3>동작 방식</h3>
 * <ol>
 *   <li>Grant Type 확인 ("urn:ietf:params:oauth:grant-type:authenticated-user")</li>
 *   <li>이미 토큰이 있는지 확인</li>
 *   <li>OAuth2AuthenticatedUserGrantRequest 생성</li>
 *   <li>RestClientAuthenticatedUserTokenResponseClient로 토큰 요청</li>
 *   <li>OAuth2AuthorizedClient 생성 및 반환</li>
 * </ol>
 *
 * @since 2024.12
 */
@Slf4j
public class AuthenticatedUserOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {

    private static final AuthorizationGrantType AUTHENTICATED_USER =
            new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user");

    private OAuth2AccessTokenResponseClient<OAuth2AuthenticatedUserGrantRequest> accessTokenResponseClient =
            new RestClientAuthenticatedUserTokenResponseClient();

    /**
     * 기본 생성자
     */
    public AuthenticatedUserOAuth2AuthorizedClientProvider() {
    }

    /**
     * Custom AccessTokenResponseClient 설정
     */
    public void setAccessTokenResponseClient(
            OAuth2AccessTokenResponseClient<OAuth2AuthenticatedUserGrantRequest> accessTokenResponseClient) {
        Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
        this.accessTokenResponseClient = accessTokenResponseClient;
    }

    @Override
    @Nullable
    public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
        Assert.notNull(context, "context cannot be null");

        ClientRegistration clientRegistration = context.getClientRegistration();

        // Grant Type 확인
        if (!AUTHENTICATED_USER.equals(clientRegistration.getAuthorizationGrantType())) {
            return null;
        }

        // 이미 OAuth2AuthorizedClient가 있으면 null 반환 (갱신 불필요)
        OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
        if (authorizedClient != null) {
            return null;
        }

        // Principal (사용자 인증 정보) 확인
        Authentication authentication = context.getPrincipal();
        if (authentication == null) {
            OAuth2Error error = new OAuth2Error("invalid_principal",
                    "Principal is required for authenticated-user grant", null);
            throw new OAuth2AuthenticationException(error);
        }

        String username = authentication.getName();
        String deviceId = context.getAttribute("device_id");

        if (log.isDebugEnabled()) {
            log.debug("Authorizing user '{}' with authenticated-user grant", username);
        }

        HttpServletRequest request = context.getAttribute(HttpServletRequest.class.getName());
        HttpServletResponse response = context.getAttribute(HttpServletResponse.class.getName());

        log.debug("Extracted from OAuth2AuthorizationContext: request={}, response={}",
                request != null ? request.getClass().getSimpleName() : "null",
                response != null ? response.getClass().getSimpleName() : "null");

        // OAuth2AuthenticatedUserGrantRequest 생성
        OAuth2AuthenticatedUserGrantRequest grantRequest =
                new OAuth2AuthenticatedUserGrantRequest(clientRegistration, username, deviceId);

        // RestClientAuthenticatedUserTokenResponseClient에 request/response 설정
        if (this.accessTokenResponseClient instanceof RestClientAuthenticatedUserTokenResponseClient client) {
            log.debug("Setting request/response to RestClientAuthenticatedUserTokenResponseClient");
            client.setRequest(request);
            client.setResponse(response);
        } else {
            log.warn("accessTokenResponseClient is not an instance of RestClientAuthenticatedUserTokenResponseClient: {}",
                    this.accessTokenResponseClient.getClass().getName());
        }

        // RestClient로 /oauth2/token 호출하여 토큰 획득
        OAuth2AccessTokenResponse tokenResponse;
        try {
            tokenResponse = this.accessTokenResponseClient.getTokenResponse(grantRequest);
        } catch (OAuth2AuthenticationException ex) {
            log.error("Failed to obtain access token for user '{}'", username, ex);
            throw ex;
        }

        if (log.isDebugEnabled()) {
            log.debug("Successfully obtained access token for user '{}'", username);
        }

        // OAuth2AuthorizedClient 생성
        return new OAuth2AuthorizedClient(
                clientRegistration,
                username,
                tokenResponse.getAccessToken(),
                tokenResponse.getRefreshToken());
    }
}
