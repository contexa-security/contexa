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


@Slf4j
@AutoConfiguration
@AutoConfigureAfter(IdentitySecurityCoreAutoConfiguration.class)
@RequiredArgsConstructor
public class IdentityOAuth2AutoConfiguration {

    private final TransactionTemplate transactionTemplate;

    
    @Bean
    public OAuth2StateAdapter oauth2StateAdapter() {
        log.info("Registering OAuth2StateAdapter bean");
        return new OAuth2StateAdapter();
    }

    
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        log.info("Registering JwtDecoder bean for Resource Server");
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        log.info("Registering JwtEncoder bean for Authorization Server");
        return new NimbusJwtEncoder(jwkSource);
    }

    
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

        log.info("Registering JdbcOAuth2AuthorizationService bean");
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        log.info("Registering JdbcRegisteredClientRepository bean");

        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);

        
        RegisteredClient existingClient = repository.findByClientId("aidc-client");

        if (existingClient == null) {
            log.info("Creating default OAuth2 client: aidc-client");

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

    
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        String issuerUri = "http://localhost:8080"; 

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

    
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        log.info("Registering OAuth2TokenCustomizer for custom claims (device_id, roles)");

        return context -> {
            
            Object deviceId = context.get("device_id");
            if (deviceId != null) {
                context.getClaims().claim("device_id", deviceId);
                log.debug("Added device_id claim: {}", deviceId);
            }

            
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

    
    @Bean
    public TokenValidator oauth2TokenValidator(
            JwtDecoder jwtDecoder,
            RefreshTokenStore refreshTokenStore,
            OAuth2AuthorizationService authorizationService,
            AuthContextProperties authContextProperties) {

        log.info("Registering OAuth2TokenValidator bean (RSA-based)");

        
        
        long rotateThresholdMillis = authContextProperties.getRefreshTokenValidity() / 2;

        return new OAuth2TokenValidator(
                jwtDecoder,
                refreshTokenStore,
                authorizationService,
                rotateThresholdMillis
        );
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

    
    @Bean("oauth2TokenSuccessHandler")
    public AuthenticationSuccessHandler oauth2TokenSuccessHandler() {
        log.info("Registering OAuth2TokenSuccessHandler bean for internal/external token request handling");
        return new OAuth2TokenSuccessHandler();
    }

    
    @Bean("oauth2LogoutHandler")
    public LogoutHandler oauth2LogoutHandler(
            OAuth2TokenService tokenService,
            AuthResponseWriter responseWriter) {

        log.info("Registering OAuth2LogoutHandler bean");
        return new OAuth2LogoutHandler(tokenService, responseWriter);
    }

    
    @Bean("oauth2LogoutSuccessHandler")
    public LogoutSuccessHandler oauth2LogoutSuccessHandler(ObjectMapper objectMapper) {
        log.info("Registering OAuth2LogoutSuccessHandler bean");
        return new OAuth2LogoutSuccessHandler(objectMapper);
    }

    

    
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
                
                .authorizationGrantType(
                        new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user"))
                
                .tokenUri(tokenUri)
                
                .scope("read", "write", "admin")
                .build();

        return new InMemoryClientRegistrationRepository(registration);
    }

    
    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository() {
        log.info("Registering OAuth2AuthorizedClientRepository (HttpSession-based)");
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            ObjectProvider<FilterChainProxy> filterChainProxyProvider,
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService) {

        log.info("Registering OAuth2AuthorizedClientManager with custom providers (ObjectProvider-based lazy loading)");

        
        
        RestClientAuthenticatedUserTokenResponseClient tokenResponseClient =
                new RestClientAuthenticatedUserTokenResponseClient();
        tokenResponseClient.setFilterChainProxyProvider(filterChainProxyProvider);

        
        tokenResponseClient.setClientSecretBasicConverter(
                new org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter());

        
        tokenResponseClient.setClientSecretAuthenticationProvider(
                new org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider(
                        registeredClientRepository,
                        authorizationService
                ));

        
        AuthenticatedUserOAuth2AuthorizedClientProvider authenticatedUserProvider =
                new AuthenticatedUserOAuth2AuthorizedClientProvider();
        authenticatedUserProvider.setAccessTokenResponseClient(tokenResponseClient);

        
        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        
                        .provider(authenticatedUserProvider)
                        
                        .refreshToken()
                        .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(
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

        log.info("OAuth2AuthorizedClientManager configured successfully with deferred OAuth2TokenEndpointFilter loading");

        return authorizedClientManager;
    }

}
