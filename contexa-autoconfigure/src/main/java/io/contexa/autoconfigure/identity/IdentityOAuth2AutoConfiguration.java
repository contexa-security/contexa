package io.contexa.autoconfigure.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateAdapter;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.AuthenticatedUserOAuth2AuthorizedClientProvider;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.RestClientAuthenticatedUserTokenResponseClient;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexaidentity.security.handler.logout.OAuth2LogoutHandler;
import io.contexa.contexaidentity.security.handler.logout.OAuth2LogoutSuccessHandler;
import io.contexa.contexaidentity.security.handler.oauth2.OAuth2TokenSuccessHandler;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.service.OAuth2TokenService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.store.RefreshTokenStore;
import io.contexa.contexaidentity.security.token.transport.TokenTransportStrategy;
import io.contexa.contexaidentity.security.token.transport.TokenTransportStrategyFactory;
import io.contexa.contexaidentity.security.token.validator.OAuth2TokenValidator;
import io.contexa.contexaidentity.security.token.validator.TokenValidator;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
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
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.transaction.support.TransactionTemplate;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * OAuth2 Authorization Server & Client 자동 설정
 *
 * Spring Authorization Server, Resource Server, OAuth2 Client에 필요한 모든 빈을 자동으로 등록합니다.
 * 설정은 application.yml의 aidc.security.oauth2 프로퍼티를 통해 제어됩니다.
 *
 * <h3>등록되는 빈 (총 18개):</h3>
 * <ul>
 *   <li><strong>Authorization Server (11개)</strong>: oauth2StateAdapter, jwtDecoder, jwtEncoder, jwkSource,
 *       authorizationService, registeredClientRepository, authorizationServerSettings, tokenGenerator,
 *       tokenCustomizer, oauth2TokenValidator, oauth2TokenService</li>
 *   <li><strong>OAuth2 Client (3개)</strong>: clientRegistrationRepository, authorizedClientRepository,
 *       authorizedClientManager</li>
 *   <li><strong>Handlers (4개)</strong>: oauth2TokenSuccessHandler, oauth2LogoutHandler,
 *       oauth2LogoutSuccessHandler</li>
 * </ul>
 */
@Slf4j
@AutoConfiguration
@AutoConfigureAfter(IdentitySecurityCoreAutoConfiguration.class)
@RequiredArgsConstructor
public class IdentityOAuth2AutoConfiguration {

    private final TransactionTemplate transactionTemplate;

    /**
     * OAuth2 State Adapter 빈 등록
     */
    @Bean
    public OAuth2StateAdapter oauth2StateAdapter() {
        log.info("Registering OAuth2StateAdapter bean");
        return new OAuth2StateAdapter();
    }

    /**
     * Resource Server용 JwtDecoder
     * Authorization Server와 Resource Server가 동일한 서버에 있을 때 사용
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        log.info("Registering JwtDecoder bean for Resource Server");
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Authorization Server용 JwtEncoder
     * OAuth2 표준 JWT 토큰 생성에 사용
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        log.info("Registering JwtEncoder bean for Authorization Server");
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * JWK (JSON Web Key) 소스
     * JWT 서명 및 검증에 사용되는 RSA 키 쌍 제공
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        log.info("Generating RSA key pair for JWT signing");
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * RSA 키 쌍 생성
     */
    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA key pair", ex);
        }
    }

    /**
     * OAuth2 인가 정보 저장소 (JDBC 기반)
     *
     * JdbcOAuth2AuthorizationService를 사용하여 DB에 OAuth2 인가 정보 저장
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {

        log.info("Registering JdbcOAuth2AuthorizationService bean");
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 등록된 클라이언트 저장소 (JDBC 기반)
     *
     * JdbcRegisteredClientRepository를 사용하여 DB에 OAuth2 클라이언트 정보 저장
     * 기본 클라이언트가 없으면 자동으로 생성하여 저장
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        log.info("Registering JdbcRegisteredClientRepository bean");

        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);

        // 기존 클라이언트 확인
        RegisteredClient existingClient = repository.findByClientId("aidc-client");

        if (existingClient == null) {
            log.info("Creating default OAuth2 client: aidc-client");

            RegisteredClient defaultClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("aidc-client")
                    .clientSecret("{noop}secret") // {noop}은 평문 비밀번호 (개발용)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    // Custom Grant Type 추가
                    .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                    .redirectUri("http://localhost:8080/login/oauth2/code/aidc-client")
                    .redirectUri("http://localhost:8080/authorized")
                    .scope("read")
                    .scope("write")
                    .scope("admin")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(false)
                            .requireProofKey(false)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofHours(1))
                            .refreshTokenTimeToLive(Duration.ofDays(1))
                            .reuseRefreshTokens(false)
                            .build())
                    .build();

            transactionTemplate.executeWithoutResult(status -> {
                repository.save(defaultClient);
                if (log.isDebugEnabled()) {
                    log.debug("Saved OAuth2Authorization for user: {} in transaction", defaultClient.getClientId());
                }
            });

            log.info("Default OAuth2 client saved to database: clientId={}, grantTypes={}",
                    defaultClient.getClientId(),
                    defaultClient.getAuthorizationGrantTypes());
        } else {
            log.info("Default OAuth2 client already exists in database: clientId={}",
                    existingClient.getClientId());
        }

        return repository;
    }

    /**
     * Authorization Server 설정
     *
     * OAuth2 엔드포인트 경로 및 기타 설정 정의
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        String issuerUri = "http://localhost:8080"; // TODO: application.yml에서 읽어오기

        log.info("Registering AuthorizationServerSettings bean with issuerUri={}", issuerUri);

        return AuthorizationServerSettings.builder()
                .issuer(issuerUri)
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .jwkSetEndpoint("/oauth2/jwks")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .oidcClientRegistrationEndpoint("/connect/register")
                .oidcUserInfoEndpoint("/userinfo")
                .build();
    }

    /**
     * OAuth2TokenGenerator 빈 등록
     *
     * JWT Access Token과 OAuth2 Refresh Token을 생성하는 통합 토큰 생성기
     */
    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(
            JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer) {

        log.info("Registering OAuth2TokenGenerator bean with JwtGenerator and RefreshTokenGenerator");

        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(tokenCustomizer);

        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
    }

    /**
     * OAuth2TokenCustomizer 빈 등록
     *
     * JWT에 커스텀 클레임 추가 (device_id, roles 등)
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        log.info("Registering OAuth2TokenCustomizer for custom claims (device_id, roles)");

        return context -> {
            // device_id 클레임 추가
            Object deviceId = context.get("device_id");
            if (deviceId != null) {
                context.getClaims().claim("device_id", deviceId);
                log.debug("Added device_id claim: {}", deviceId);
            }

            // roles 클레임 추가 (Authentication의 authorities 에서 추출)
            if (context.getPrincipal() != null) {
                var authorities = context.getPrincipal().getAuthorities();
                if (authorities != null && !authorities.isEmpty()) {
                    var roles = authorities.stream()
                            .map(grantedAuthority -> grantedAuthority.getAuthority())
                            .toList();
                    context.getClaims().claim("roles", roles);
                    log.debug("Added roles claim: {}", roles);
                }
            }
        };
    }

    /**
     * OAuth2TokenValidator 빈 등록
     * <p>
     * JwtTokenValidator와 동일한 패턴으로 OAuth2 토큰 검증을 수행합니다.
     * TokenService가 이 TokenValidator를 주입받아 사용합니다.
     */
    @Bean
    public TokenValidator oauth2TokenValidator(
            JwtDecoder jwtDecoder,
            RefreshTokenStore refreshTokenStore,
            OAuth2AuthorizationService authorizationService,
            AuthContextProperties authContextProperties) {

        log.info("Registering OAuth2TokenValidator bean (RSA-based)");

        // Refresh Token 회전 임계값 (밀리초)
        // 남은 유효 기간이 이 값 이하이면 회전 필요
        long rotateThresholdMillis = authContextProperties.getRefreshTokenValidity() / 2;

        return new OAuth2TokenValidator(
                jwtDecoder,
                refreshTokenStore,
                authorizationService,
                rotateThresholdMillis
        );
    }


    /**
     * OAuth2TokenService 빈 등록
     *
     * OAuth2 Client 프레임워크를 활용한 토큰 획득 서비스 (RSA 기반)
     * - OAuth2AuthorizedClientManager: OAuth2 표준 토큰 획득 (내부/외부 인가서버 모두 지원)
     * - OAuth2AuthorizationService: JDBC 기반 Authorization 저장소
     * - RefreshTokenStore: 고급 보안 기능 (블랙리스트, 중복 로그인 제어, 토큰 재사용 감지)
     * - TokenValidator: 토큰 검증 및 무효화 (RSA 기반 검증)
     * - ClientRegistrationRepository: OAuth2 Client 등록 정보
     * - JwtDecoder: RSA 공개키 기반 토큰 파싱 및 검증
     */
    @Bean
    public TokenService oauth2TokenService(
            OAuth2AuthorizedClientManager authorizedClientManager,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizationService authorizationService,
            RefreshTokenStore refreshTokenStore,
            TokenValidator oauth2TokenValidator,
            JwtDecoder jwtDecoder,
            AuthContextProperties authContextProperties,
            ObjectMapper objectMapper) {

        log.info("Registering OAuth2TokenService bean with OAuth2AuthorizedClientManager");

        TokenTransportStrategy transport = TokenTransportStrategyFactory.create(authContextProperties);

        return new OAuth2TokenService(
                authorizedClientManager,
                clientRegistrationRepository,
                authorizationService,
                refreshTokenStore,
                oauth2TokenValidator,
                jwtDecoder,
                authContextProperties,
                objectMapper,
                transport
        );
    }

    /**
     * OAuth2 Token Success Handler 빈 등록
     *
     * <p>OAuth2StateConfigurer에서 tokenEndpoint.accessTokenResponseHandler()로 자동 설정됩니다.
     * 내부 호출 시 ThreadLocal에 응답을 저장하여 HTTP 통신 없이 토큰을 획득할 수 있습니다.
     *
     * @since 2025.01
     * @see io.contexa.contexaidentity.security.handler.oauth2.OAuth2TokenSuccessHandler
     * @see io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateConfigurer
     */
    @Bean("oauth2TokenSuccessHandler")
    public AuthenticationSuccessHandler oauth2TokenSuccessHandler() {
        log.info("Registering OAuth2TokenSuccessHandler bean for internal/external token request handling");
        return new OAuth2TokenSuccessHandler();
    }

    /**
     * OAuth2 LogoutHandler 빈 등록
     *
     * 로그아웃 시 Refresh Token 무효화, 블랙리스트 추가, 쿠키 삭제, JSON 응답 작성
     */
    @Bean("oauth2LogoutHandler")
    public LogoutHandler oauth2LogoutHandler(
            OAuth2TokenService tokenService,
            AuthResponseWriter responseWriter) {

        log.info("Registering OAuth2LogoutHandler bean");
        return new OAuth2LogoutHandler(tokenService, responseWriter);
    }

    /**
     * OAuth2 LogoutSuccessHandler 빈 등록
     *
     * 로그아웃 성공 시 JSON 응답 반환
     */
    @Bean("oauth2LogoutSuccessHandler")
    public LogoutSuccessHandler oauth2LogoutSuccessHandler(ObjectMapper objectMapper) {
        log.info("Registering OAuth2LogoutSuccessHandler bean");
        return new OAuth2LogoutSuccessHandler(objectMapper);
    }

    // ========== OAuth2 Client 설정 (3개 빈) ==========

    /**
     * ClientRegistrationRepository 빈 등록
     *
     * <p>내부 Authorization Server를 클라이언트로 등록합니다.
     * Spring OAuth2 Client 프레임워크를 활용하여 Authorization Server로부터 OAuth2 토큰을 획득합니다.
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        String registrationId = "aidc-internal";
        String clientId = "aidc-client";
        String clientSecret = "secret";
        String tokenUri = "http://localhost:8081/oauth2/token";

        log.info("Registering OAuth2 Client: registrationId={}, clientId={}", registrationId, clientId);

        ClientRegistration registration = ClientRegistration
                .withRegistrationId(registrationId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                // Custom Grant Type: authenticated-user
                .authorizationGrantType(
                        new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user"))
                // Token URI
                .tokenUri(tokenUri)
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
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService) {

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
