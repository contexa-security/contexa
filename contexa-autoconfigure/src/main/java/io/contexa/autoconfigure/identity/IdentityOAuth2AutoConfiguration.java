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
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
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

@Slf4j
@AutoConfiguration
@AutoConfigureAfter(IdentitySecurityCoreAutoConfiguration.class)
@ConditionalOnBean(PlatformConfig.class)
@RequiredArgsConstructor
public class IdentityOAuth2AutoConfiguration {

    private final TransactionTemplate transactionTemplate;

    @Bean
    public OAuth2StateAdapter oauth2StateAdapter() {
        return new OAuth2StateAdapter();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
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

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA key pair", ex);
        }
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {

        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {

        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);

        RegisteredClient existingClient = repository.findByClientId("aidc-client");

        if (existingClient == null) {

            RegisteredClient defaultClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("aidc-client")
                    .clientSecret("{noop}secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)

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
                }
            });

        } else {
        }

        return repository;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        String issuerUri = "http://localhost:8080";

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

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(
            JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer) {

        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(tokenCustomizer);

        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {

        return context -> {

            Object deviceId = context.get("device_id");
            if (deviceId != null) {
                context.getClaims().claim("device_id", deviceId);
            }

            if (context.getPrincipal() != null) {
                var authorities = context.getPrincipal().getAuthorities();
                if (authorities != null && !authorities.isEmpty()) {
                    var roles = authorities.stream()
                            .map(grantedAuthority -> grantedAuthority.getAuthority())
                            .toList();
                    context.getClaims().claim("roles", roles);
                }
            }
        };
    }

    @Bean
    public TokenValidator oauth2TokenValidator(
            JwtDecoder jwtDecoder,
            RefreshTokenStore refreshTokenStore,
            OAuth2AuthorizationService authorizationService,
            AuthContextProperties authContextProperties) {

        long rotateThresholdMillis = authContextProperties.getRefreshTokenValidity() / 2;

        return new OAuth2TokenValidator(
                jwtDecoder,
                refreshTokenStore,
                authorizationService,
                rotateThresholdMillis);
    }

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
                transport);
    }

    @Bean("oauth2TokenSuccessHandler")
    public AuthenticationSuccessHandler oauth2TokenSuccessHandler() {
        return new OAuth2TokenSuccessHandler();
    }

    @Bean("oauth2LogoutHandler")
    public LogoutHandler oauth2LogoutHandler(
            OAuth2TokenService tokenService,
            AuthResponseWriter responseWriter) {

        return new OAuth2LogoutHandler(tokenService, responseWriter);
    }

    @Bean("oauth2LogoutSuccessHandler")
    public LogoutSuccessHandler oauth2LogoutSuccessHandler(ObjectMapper objectMapper) {
        return new OAuth2LogoutSuccessHandler(objectMapper);
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        String registrationId = "aidc-internal";
        String clientId = "aidc-client";
        String clientSecret = "secret";
        String tokenUri = "http://localhost:8081/oauth2/token";

        ClientRegistration registration = ClientRegistration
                .withRegistrationId(registrationId)
                .clientId(clientId)
                .clientSecret(clientSecret)

                .authorizationGrantType(
                        new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user"))

                .tokenUri(tokenUri)

                .scope("read", "write", "admin")
                .build();

        return new InMemoryClientRegistrationRepository(registration);
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            ObjectProvider<FilterChainProxy> filterChainProxyProvider,
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService) {

        RestClientAuthenticatedUserTokenResponseClient tokenResponseClient = new RestClientAuthenticatedUserTokenResponseClient();
        tokenResponseClient.setFilterChainProxyProvider(filterChainProxyProvider);

        tokenResponseClient.setClientSecretBasicConverter(
                new org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter());

        tokenResponseClient.setClientSecretAuthenticationProvider(
                new org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider(
                        registeredClientRepository,
                        authorizationService));

        AuthenticatedUserOAuth2AuthorizedClientProvider authenticatedUserProvider = new AuthenticatedUserOAuth2AuthorizedClientProvider();
        authenticatedUserProvider.setAccessTokenResponseClient(tokenResponseClient);

        OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()

                .provider(authenticatedUserProvider)

                .refreshToken()
                .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository,
                authorizedClientRepository);

        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        authorizedClientManager.setContextAttributesMapper(authorizeRequest -> {
            Map<String, Object> contextAttributes = new HashMap<>();

            Object request = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
            Object response = authorizeRequest.getAttribute(HttpServletResponse.class.getName());

            if (request != null) {
                contextAttributes.put(HttpServletRequest.class.getName(), request);
            }
            if (response != null) {
                contextAttributes.put(HttpServletResponse.class.getName(), response);
            }

            Object deviceId = authorizeRequest.getAttribute("device_id");
            if (deviceId != null) {
                contextAttributes.put("device_id", deviceId);
            }

            return contextAttributes;
        });

        return authorizedClientManager;
    }
}
