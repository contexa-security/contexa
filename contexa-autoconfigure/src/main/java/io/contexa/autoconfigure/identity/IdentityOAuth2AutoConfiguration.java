package io.contexa.autoconfigure.identity;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateAdapter;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.AuthenticatedUserOAuth2AuthorizedClientProvider;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.RestClientAuthenticatedUserTokenResponseClient;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.MfaGrantedAuthority;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.MfaGrantedAuthorityMixin;
import io.contexa.contexaidentity.security.handler.logout.CompositeLogoutHandler;
import io.contexa.contexaidentity.security.handler.logout.LogoutStrategy;
import io.contexa.contexaidentity.security.handler.logout.OAuth2LogoutStrategy;
import io.contexa.contexaidentity.security.handler.logout.OAuth2LogoutSuccessHandler;
import io.contexa.contexaidentity.security.handler.logout.SessionLogoutStrategy;
import io.contexa.contexaidentity.security.handler.logout.ZeroTrustLogoutStrategy;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaidentity.security.handler.oauth2.OAuth2TokenSuccessHandler;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.OAuth2TokenSettings;
import io.contexa.contexaidentity.security.token.service.OAuth2TokenService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportStrategy;
import io.contexa.contexaidentity.security.token.transport.TokenTransportStrategyFactory;
import io.contexa.contexaidentity.security.token.validator.OAuth2TokenValidator;
import io.contexa.contexaidentity.security.token.validator.TokenValidator;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
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
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
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
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@AutoConfiguration
@AutoConfigureAfter(IdentitySecurityCoreAutoConfiguration.class)
@ConditionalOnBean(PlatformConfig.class)
@RequiredArgsConstructor
public class IdentityOAuth2AutoConfiguration {

    private final TransactionTemplate transactionTemplate;
    private final AuthContextProperties authContextProperties;

    @Bean
    @ConditionalOnMissingBean(OAuth2StateAdapter.class)
    public OAuth2StateAdapter oauth2StateAdapter() {
        return new OAuth2StateAdapter();
    }

    @Bean
    @ConditionalOnMissingBean(JwtDecoder.class)
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    @ConditionalOnMissingBean(JwtEncoder.class)
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    @ConditionalOnMissingBean(JWKSource.class)
    public JWKSource<SecurityContext> jwkSource() {
        OAuth2TokenSettings oauth2 = authContextProperties.getOauth2();
        String keyStorePath = oauth2.getJwkKeyStorePath();

        if (keyStorePath != null && !keyStorePath.isBlank()) {
            return loadJwkFromKeyStore(oauth2);
        }

        log.error("[OAuth2] JWK KeyStore not configured (spring.auth.oauth2.jwk-key-store-path) - using ephemeral RSA key. "
                + "Tokens will be invalidated on restart");

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

    private JWKSource<SecurityContext> loadJwkFromKeyStore(OAuth2TokenSettings oauth2) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream is = getClass().getClassLoader().getResourceAsStream(oauth2.getJwkKeyStorePath())) {
                if (is == null) {
                    throw new IllegalStateException("KeyStore not found: " + oauth2.getJwkKeyStorePath());
                }
                char[] storePassword = oauth2.getJwkKeyStorePassword() != null
                        ? oauth2.getJwkKeyStorePassword().toCharArray() : new char[0];
                keyStore.load(is, storePassword);
            }

            String alias = oauth2.getJwkKeyAlias();
            char[] keyPassword = oauth2.getJwkKeyPassword() != null
                    ? oauth2.getJwkKeyPassword().toCharArray()
                    : (oauth2.getJwkKeyStorePassword() != null ? oauth2.getJwkKeyStorePassword().toCharArray() : new char[0]);

            RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey(alias, keyPassword);
            RSAPublicKey publicKey = (RSAPublicKey) keyStore.getCertificate(alias).getPublicKey();

            RSAKey rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(alias)
                    .build();

            JWKSet jwkSet = new JWKSet(rsaKey);
            return new ImmutableJWKSet<>(jwkSet);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load JWK from KeyStore: " + oauth2.getJwkKeyStorePath(), e);
        }
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
    @ConditionalOnMissingBean(OAuth2AuthorizationService.class)
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {

        JdbcOAuth2AuthorizationService jdbcService =
                new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);

        ObjectMapper authorizationObjectMapper = new ObjectMapper();
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        authorizationObjectMapper.registerModules(SecurityJackson2Modules.getModules(classLoader));
        authorizationObjectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        authorizationObjectMapper.addMixIn(MfaGrantedAuthority.class, MfaGrantedAuthorityMixin.class);
        registerImmutableCollectionMixins(authorizationObjectMapper);

        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
        rowMapper.setObjectMapper(authorizationObjectMapper);
        jdbcService.setAuthorizationRowMapper(rowMapper);

        return new DeviceAwareOAuth2AuthorizationService(jdbcService, jdbcTemplate, authContextProperties);
    }

    @Bean
    @ConditionalOnMissingBean(RegisteredClientRepository.class)
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {

        OAuth2TokenSettings oauth2 = authContextProperties.getOauth2();
        String clientId = oauth2.getClientId();

        String clientSecret = oauth2.getClientSecret();
        if (clientSecret == null || clientSecret.isBlank()) {
            clientSecret = UUID.randomUUID().toString();
            log.error("[OAuth2] Client secret not configured (spring.auth.oauth2.client-secret) - generated random secret. "
                    + "Configure explicitly for production");
        }

        String redirectUri = oauth2.getRedirectUri();
        String authorizedUri = oauth2.getAuthorizedUri();

        initializeAuthorizationServerSchema(jdbcTemplate.getDataSource());

        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);

        RegisteredClient existingClient = repository.findByClientId(clientId);

        if (existingClient == null) {

            RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(clientId)
                    .clientSecret("{noop}" + clientSecret)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
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
                            .accessTokenTimeToLive(Duration.ofMillis(authContextProperties.getAccessTokenValidity()))
                            .refreshTokenTimeToLive(Duration.ofMillis(authContextProperties.getRefreshTokenValidity()))
                            .reuseRefreshTokens(false)
                            .build());

            if (redirectUri != null && !redirectUri.isBlank()) {
                builder.redirectUri(redirectUri);
            }
            if (authorizedUri != null && !authorizedUri.isBlank()) {
                builder.redirectUri(authorizedUri);
            }

            RegisteredClient defaultClient = builder.build();

            transactionTemplate.executeWithoutResult(status -> {
                repository.save(defaultClient);
            });
        }

        return repository;
    }

    private void initializeAuthorizationServerSchema(DataSource dataSource) {
        if (dataSource == null) {
            throw new IllegalStateException("DataSource is required for OAuth2 authorization server schema initialization");
        }

        ResourceDatabasePopulator populator = new ResourceDatabasePopulator(
                new org.springframework.core.io.ClassPathResource("contexa-oauth2-authorization-schema.sql"));
        populator.setContinueOnError(false);
        populator.execute(dataSource);
    }

    @Bean
    @ConditionalOnMissingBean(AuthorizationServerSettings.class)
    public AuthorizationServerSettings authorizationServerSettings() {
        OAuth2TokenSettings oauth2 = authContextProperties.getOauth2();
        String issuerUri = oauth2.getIssuerUri();

        if (issuerUri == null || issuerUri.isBlank()) {
            log.error("[OAuth2] Issuer URI not configured (spring.auth.oauth2.issuer-uri) - "
                    + "authorization server may not function correctly");
        }

        AuthorizationServerSettings.Builder builder = AuthorizationServerSettings.builder()
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .jwkSetEndpoint("/oauth2/jwks")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .oidcClientRegistrationEndpoint("/connect/register")
                .oidcUserInfoEndpoint("/userinfo");

        if (issuerUri != null && !issuerUri.isBlank()) {
            builder.issuer(issuerUri);
        }

        return builder.build();
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2TokenGenerator.class)
    public OAuth2TokenGenerator<?> tokenGenerator(
            JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer) {

        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(tokenCustomizer);

        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2TokenCustomizer.class)
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {

        return context -> {

            Object deviceId = context.get("device_id");
            if (deviceId != null) {
                context.getClaims().claim("device_id", deviceId);
            }

            if (context.getPrincipal() != null) {
                var authorities = context.getPrincipal().getAuthorities();
                if (authorities != null && !authorities.isEmpty()) {
                    List<String> roles = authorities.stream()
                            .map(grantedAuthority -> {
                                String auth = grantedAuthority.getAuthority();
                                return auth.startsWith("ROLE_") ? auth.substring(5) : auth;
                            })
                            .collect(Collectors.toList());
                    context.getClaims().claim("roles", roles);
                }
            }
        };
    }

    @Bean
    @ConditionalOnMissingBean(TokenValidator.class)
    public TokenValidator oauth2TokenValidator(
            JwtDecoder jwtDecoder,
            OAuth2AuthorizationService authorizationService) {

        long rotateThresholdMillis = authContextProperties.getRefreshTokenValidity() / 2;

        return new OAuth2TokenValidator(
                jwtDecoder,
                authorizationService,
                rotateThresholdMillis);
    }

    @Bean
    @ConditionalOnMissingBean(TokenService.class)
    public TokenService oauth2TokenService(
            OAuth2AuthorizedClientManager authorizedClientManager,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizationService authorizationService,
            TokenValidator oauth2TokenValidator,
            ObjectMapper objectMapper) {

        TokenTransportStrategy transport = TokenTransportStrategyFactory.create(authContextProperties);

        return new OAuth2TokenService(
                authorizedClientManager,
                clientRegistrationRepository,
                authorizationService,
                oauth2TokenValidator,
                authContextProperties,
                objectMapper,
                transport);
    }

    @Bean("oauth2TokenSuccessHandler")
    @ConditionalOnMissingBean(name = "oauth2TokenSuccessHandler")
    public AuthenticationSuccessHandler oauth2TokenSuccessHandler() {
        return new OAuth2TokenSuccessHandler();
    }

    @Bean("compositeLogoutHandler")
    @ConditionalOnMissingBean(name = "compositeLogoutHandler")
    public CompositeLogoutHandler compositeLogoutHandler(
            TokenService tokenService,
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties,
            ObjectProvider<ZeroTrustSecurityService> zeroTrustSecurityServiceProvider,
            SessionIdResolver sessionIdResolver,
            DeviceAwareOAuth2AuthorizationService authorizationService) {

        ZeroTrustSecurityService zeroTrustService = zeroTrustSecurityServiceProvider.getIfAvailable();

        List<LogoutStrategy> strategies = new ArrayList<>();
        strategies.add(new SessionLogoutStrategy(new HttpSessionCsrfTokenRepository(), authContextProperties));
        strategies.add(new OAuth2LogoutStrategy(tokenService));
        if (zeroTrustService != null) {
            strategies.add(new ZeroTrustLogoutStrategy(zeroTrustService, sessionIdResolver));
        }

        return new CompositeLogoutHandler(
                strategies,
                tokenService,
                responseWriter,
                zeroTrustService,
                authorizationService);
    }

    @Bean("oauth2LogoutSuccessHandler")
    @ConditionalOnMissingBean(name = "oauth2LogoutSuccessHandler")
    public LogoutSuccessHandler oauth2LogoutSuccessHandler(ObjectMapper objectMapper) {
        return new OAuth2LogoutSuccessHandler(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(ClientRegistrationRepository.class)
    public ClientRegistrationRepository clientRegistrationRepository() {
        OAuth2TokenSettings oauth2 = authContextProperties.getOauth2();

        String registrationId = "aidc-internal";
        String clientId = oauth2.getClientId();
        String clientSecret = oauth2.getClientSecret() != null ? oauth2.getClientSecret() : "";
        String tokenUri = oauth2.getIssuerUri() != null
                ? oauth2.getIssuerUri() + oauth2.getTokenEndpoint()
                : oauth2.getTokenEndpoint();

        String[] scopes = oauth2.getScope() != null ? oauth2.getScope().split(",") : new String[]{"read"};

        ClientRegistration registration = ClientRegistration
                .withRegistrationId(registrationId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .authorizationGrantType(
                        new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user"))
                .tokenUri(tokenUri)
                .scope(scopes)
                .build();

        return new InMemoryClientRegistrationRepository(registration);
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizedClientRepository.class)
    public OAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizedClientManager.class)
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

    private void registerImmutableCollectionMixins(ObjectMapper objectMapper) {
        String[] immutableTypes = {
                "java.util.ImmutableCollections$ListN",
                "java.util.ImmutableCollections$List12",
                "java.util.ImmutableCollections$SubList"
        };
        for (String className : immutableTypes) {
            try {
                objectMapper.addMixIn(Class.forName(className), ImmutableListDeserializationMixin.class);
            } catch (ClassNotFoundException ignored) {
            }
        }
    }

    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    @JsonDeserialize(as = ArrayList.class)
    private abstract static class ImmutableListDeserializationMixin {
    }
}
