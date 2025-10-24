package io.contexa.contexaidentity.security.config;

import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.AuthenticatedUserOAuth2AuthorizedClientProvider;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.RestClientAuthenticatedUserTokenResponseClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.FilterChainProxy;

import java.util.HashMap;
import java.util.Map;

/**
 * OAuth2 Client 설정
 *
 * <p>Spring OAuth2 Client 프레임워크를 활용하여
 * Authorization Server 로부터 OAuth2 토큰을 획득합니다.
 *
 * <h3>주요 컴포넌트</h3>
 * <ul>
 *   <li>ClientRegistrationRepository: OAuth2 클라이언트 등록 정보 관리</li>
 *   <li>OAuth2AuthorizedClientRepository: 획득한 토큰 저장/조회</li>
 *   <li>OAuth2AuthorizedClientManager: 토큰 획득 및 갱신 관리</li>
 * </ul>
 *
 * @since 2024.12
 */
@Slf4j
@Configuration
public class OAuth2ClientConfiguration {

    private static final String CLIENT_REGISTRATION_ID = "aidc-internal";
    private static final String CLIENT_ID = "aidc-client";
    private static final String CLIENT_SECRET = "secret";
    private static final String TOKEN_URI = "http://localhost:8081/oauth2/token";

    /**
     * ClientRegistrationRepository 빈 등록
     *
     * <p>내부 Authorization Server를 클라이언트로 등록합니다.
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        log.info("Registering OAuth2 Client: registrationId={}, clientId={}", CLIENT_REGISTRATION_ID, CLIENT_ID);

        ClientRegistration registration = ClientRegistration
                .withRegistrationId(CLIENT_REGISTRATION_ID)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                // Custom Grant Type: authenticated-user
                .authorizationGrantType(
                        new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user"))
                // Refresh Token Grant Type
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // Token URI
                .tokenUri(TOKEN_URI)
                // Scopes
                .scope("read", "write", "admin")
                .build();

        return new InMemoryClientRegistrationRepository(registration);
    }

    /**
     * OAuth2AuthorizedClientRepository 빈 등록
     *
     * <p>획득한 OAuth2AuthorizedClient를 HTTP Session에 저장합니다.
     */
    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository() {
        log.info("Registering OAuth2AuthorizedClientRepository (HttpSession-based)");
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    /**
     * OAuth2AuthorizedClientManager 빈 등록
     *
     * <p>토큰 획득 및 갱신을 관리하는 중앙 컴포넌트입니다.
     *
     * <h4>지원하는 Grant Type</h4>
     * <ol>
     *   <li>authenticated-user: 사용자 인증 기반 토큰 획득 (내부 Filter 직접 호출)</li>
     *   <li>refresh_token: Refresh Token 기반 토큰 갱신</li>
     * </ol>
     *
     * <h4>순환 의존성 해결</h4>
     * <p>ObjectProvider를 사용하여 FilterChainProxy 지연 로딩:
     * <ul>
     *   <li>authorizedClientManager 빈 생성 시점에는 FilterChainProxy 접근하지 않음</li>
     *   <li>RestClientAuthenticatedUserTokenResponseClient가 첫 사용 시 ObjectProvider.getObject() 호출</li>
     *   <li>이렇게 하면 authorizedClientManager → FilterChainProxy → authorizedClientManager 순환 방지</li>
     * </ul>
     */
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            ObjectProvider<FilterChainProxy> filterChainProxyProvider,
            org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository registeredClientRepository,
            org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizationService) {

        log.info("Registering OAuth2AuthorizedClientManager with custom providers (ObjectProvider-based lazy loading)");

        // RestClientAuthenticatedUserTokenResponseClient 생성 및 설정
        // ObjectProvider를 전달 - 실제 Filter 추출은 첫 사용 시 발생
        RestClientAuthenticatedUserTokenResponseClient tokenResponseClient =
                new RestClientAuthenticatedUserTokenResponseClient();
        tokenResponseClient.setFilterChainProxyProvider(filterChainProxyProvider);

        // ClientSecretBasicAuthenticationConverter 설정
        tokenResponseClient.setClientSecretBasicConverter(
                new org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter());

        // ClientSecretAuthenticationProvider 설정
        tokenResponseClient.setClientSecretAuthenticationProvider(
                new org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider(
                        registeredClientRepository,
                        authorizationService
                ));

        // AuthenticatedUserOAuth2AuthorizedClientProvider 생성 및 설정
        AuthenticatedUserOAuth2AuthorizedClientProvider authenticatedUserProvider =
                new AuthenticatedUserOAuth2AuthorizedClientProvider();
        authenticatedUserProvider.setAccessTokenResponseClient(tokenResponseClient);

        // OAuth2AuthorizedClientProvider 조합
        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        // Custom: Authenticated User Grant
                        .provider(authenticatedUserProvider)
                        // Standard: Refresh Token Grant
                        .refreshToken()
                        .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(
                        clientRegistrationRepository,
                        authorizedClientRepository);

        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        // contextAttributesMapper 설정: OAuth2AuthorizeRequest attributes를 OAuth2AuthorizationContext로 전달
        authorizedClientManager.setContextAttributesMapper(authorizeRequest -> {
            Map<String, Object> contextAttributes = new HashMap<>();

            // HttpServletRequest/Response를 OAuth2AuthorizationContext attributes로 복사
            Object request = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
            Object response = authorizeRequest.getAttribute(HttpServletResponse.class.getName());

            if (request != null) {
                contextAttributes.put(HttpServletRequest.class.getName(), request);
            }
            if (response != null) {
                contextAttributes.put(HttpServletResponse.class.getName(), response);
            }

            // device_id도 전달
            Object deviceId = authorizeRequest.getAttribute("device_id");
            if (deviceId != null) {
                contextAttributes.put("device_id", deviceId);
            }

            return contextAttributes;
        });

        log.info("OAuth2AuthorizedClientManager configured successfully with deferred OAuth2TokenEndpointFilter loading");

        return authorizedClientManager;
    }
}
