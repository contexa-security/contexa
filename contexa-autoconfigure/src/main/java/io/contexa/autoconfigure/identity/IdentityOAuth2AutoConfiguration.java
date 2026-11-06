/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.identity;

import io.contexa.contexaidentity.security.core.adapter.state.oauth2.AuthorizationServerIssuer;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateAdapter;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacommon.security.subject.AgentClientStatusUnavailableException;
import io.contexa.contexacore.autonomous.agent.AgentDelegations;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexaidentity.security.handler.login.LoginFactClaims;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.OAuth2TokenSettings;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.AuthenticatedUserOAuth2AuthorizedClientProvider;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.InProcessAuthenticatedUserTokenResponseClient;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.InProcessOAuth2TokenEndpoint;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.InProcessRefreshTokenTokenResponseClient;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.TransientOAuth2AuthorizedClientRepository;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.MfaGrantedAuthority;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.MfaGrantedAuthorityMixin;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.handler.logout.CompositeLogoutHandler;
import io.contexa.contexaidentity.security.handler.logout.LogoutStrategy;
import io.contexa.contexaidentity.security.handler.logout.MfaFlowLogoutStrategy;
import io.contexa.contexaidentity.security.handler.logout.ExchangedTokensOfASignOut;
import io.contexa.contexaidentity.security.handler.logout.OAuth2LogoutStrategy;
import io.contexa.contexaidentity.security.handler.logout.OAuth2LogoutSuccessHandler;
import io.contexa.contexaidentity.security.handler.logout.SessionLogoutStrategy;
import io.contexa.contexaidentity.security.handler.logout.ZeroTrustLogoutStrategy;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.handler.oauth2.OAuth2TokenSuccessHandler;
import io.contexa.contexaidentity.security.token.service.AccountTokenGuard;
import io.contexa.contexaidentity.security.token.service.OAuth2TokenService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportStrategy;
import io.contexa.contexaidentity.security.token.transport.TokenTransportStrategyFactory;
import io.contexa.contexaidentity.security.token.validator.OAuth2TokenValidator;
import io.contexa.contexaidentity.security.token.validator.TokenValidator;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.UUID;
import javax.sql.DataSource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import java.security.Principal;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexacommon.jdbc.LibraryTableNames;

@Slf4j
@AutoConfiguration
@AutoConfigureAfter({IdentitySecurityCoreAutoConfiguration.class, CoreDataAutoConfiguration.class})
@ConditionalOnClass(name = "org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository")
@ConditionalOnBean(value = PlatformConfig.class, name = {"contexaJdbcTemplate", "contexaTransactionTemplate"})
@ConditionalOnOwnership(SecurityOwnershipMode.CONTEXA_OWNED)
public class IdentityOAuth2AutoConfiguration {

    private final TransactionTemplate transactionTemplate;
    private final AuthContextProperties authContextProperties;
    private final ObjectProvider<PlatformConfig> platformConfigProvider;
    private final ObjectProvider<SecurityZeroTrustProperties> zeroTrustProperties;
    private volatile String unusedInternalClientSecret;

    private static final String NOOP_SECRET_PREFIX = "{noop}";
    private static final String LEGACY_DEFAULT_CLIENT_SECRET = "173f8245-5f7d-4623-a612-aa0c68f6da4a";
    private static final String DEFAULT_SCOPE = "read";

    public IdentityOAuth2AutoConfiguration(
            @Qualifier("contexaTransactionTemplate") TransactionTemplate transactionTemplate,
            AuthContextProperties authContextProperties) {
        this(transactionTemplate, authContextProperties, null, null);
    }

    public IdentityOAuth2AutoConfiguration(
            @Qualifier("contexaTransactionTemplate") TransactionTemplate transactionTemplate,
            AuthContextProperties authContextProperties,
            ObjectProvider<PlatformConfig> platformConfigProvider) {
        this(transactionTemplate, authContextProperties, platformConfigProvider, null);
    }

    @Autowired
    public IdentityOAuth2AutoConfiguration(
            @Qualifier("contexaTransactionTemplate") TransactionTemplate transactionTemplate,
            AuthContextProperties authContextProperties,
            ObjectProvider<PlatformConfig> platformConfigProvider,
            ObjectProvider<SecurityZeroTrustProperties> zeroTrustProperties) {
        this.transactionTemplate = transactionTemplate;
        this.authContextProperties = authContextProperties;
        this.platformConfigProvider = platformConfigProvider;
        this.zeroTrustProperties = zeroTrustProperties;
    }

    @Bean(name = "contexaOauth2StateAdapter")
    @ConditionalOnMissingBean(OAuth2StateAdapter.class)
    public OAuth2StateAdapter oauth2StateAdapter() {
        return new OAuth2StateAdapter();
    }

    /**
     * Contexa's own: what Contexa issues is checked with its keys, whatever decoders the application has for its own purposes.
     * An application that verifies another issuer's tokens on Contexa's chain gives a bean of this name. Where the application
     * has no decoder, whatever asks for a JwtDecoder gets this one.
     */
    @Bean(name = "contexaJwtDecoder")
    @ConditionalOnMissingBean(JwtDecoder.class)
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource,
                                 ObjectProvider<AuthorizationServerSettings> authorizationServerSettings) {
        return jwtDecoder(jwkSource, authorizationServerSettings.getIfAvailable());
    }

    /** Beside the application's own decoders it stays out of their way. */
    @Bean(name = "contexaJwtDecoder", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaJwtDecoder")
    public JwtDecoder standbyJwtDecoder(JWKSource<SecurityContext> jwkSource,
                                        ObjectProvider<AuthorizationServerSettings> authorizationServerSettings) {
        return jwtDecoder(jwkSource, authorizationServerSettings);
    }

    /** The decoder for tokens of this authorization server, which issues them under its settings' issuer. */
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return jwtDecoder(jwkSource, authorizationServerSettings());
    }

    /**
     * Checks a token's lifetime, its issuer and its configured audiences (A1-7). The expected issuer is the one the
     * authorization server issues under.
     */
    private JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource, AuthorizationServerSettings serverSettings) {
        JwtDecoder decoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        if (decoder instanceof NimbusJwtDecoder nimbusDecoder) {
            OAuth2TokenSettings oauth2 = authContextProperties.getOauth2();
            nimbusDecoder.setJwtValidator(ResourceServerTokenValidators.of(oauth2, AuthorizationServerIssuer.of(serverSettings, oauth2)));
        }
        return decoder;
    }


    @Bean(name = "contexaJwtEncoder")
    @ConditionalOnMissingBean(JwtEncoder.class)
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    @ConditionalOnMissingBean(JWKSource.class)
    public JWKSource<SecurityContext> jwkSource() {
        OAuth2TokenSettings oauth2 = authContextProperties.getOauth2();
        String keyStorePath = oauth2.getJwkKeyStorePath();

        if (StringUtils.hasText(keyStorePath)) {
            return loadJwkFromKeyStore(oauth2);
        }

        log.warn("[OAuth2] JWK KeyStore not configured (contexa.auth.oauth2.jwk-key-store-path) - using an ephemeral RSA signing key "
                + "for the internal token engine. Tokens will be invalidated on restart; configure a persistent key for "
                + "multi-instance deployments or restart-stable token verification.");

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
            // A plain path is read from the classpath as before; "file:" lets the private key stay outside the jar.
            Resource keyStoreResource = new DefaultResourceLoader(getClass().getClassLoader())
                    .getResource(oauth2.getJwkKeyStorePath());
            if (!keyStoreResource.exists()) {
                throw new IllegalStateException("KeyStore not found: " + oauth2.getJwkKeyStorePath());
            }
            try (InputStream is = keyStoreResource.getInputStream()) {
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

    @Bean(name = "contexaAuthorizationService")
    @ConditionalOnMissingBean(OAuth2AuthorizationService.class)
    public OAuth2AuthorizationService authorizationService(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {

        JdbcOAuth2AuthorizationService jdbcService =
                new JdbcOAuth2AuthorizationService(LibraryTableNames.wrap(jdbcTemplate), registeredClientRepository);

        ObjectMapper authorizationObjectMapper = authorizationObjectMapper();

        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
        rowMapper.setObjectMapper(authorizationObjectMapper);
        jdbcService.setAuthorizationRowMapper(rowMapper);
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper parametersMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();
        parametersMapper.setObjectMapper(authorizationObjectMapper);
        jdbcService.setAuthorizationParametersMapper(parametersMapper);

        return new DeviceAwareOAuth2AuthorizationService(jdbcService, jdbcTemplate, authContextProperties, transactionTemplate);
    }

    /** The object mapper the stored authorizations (attributes and token metadata) are written and read with. */
    ObjectMapper authorizationObjectMapper() {
        ObjectMapper authorizationObjectMapper = new ObjectMapper();
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        authorizationObjectMapper.registerModules(SecurityJackson2Modules.getModules(classLoader));
        authorizationObjectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        authorizationObjectMapper.addMixIn(MfaGrantedAuthority.class, MfaGrantedAuthorityMixin.class);
        registerImmutableCollectionMixins(authorizationObjectMapper);
        return authorizationObjectMapper;
    }

    @Bean
    @ConditionalOnMissingBean(RegisteredClientRepository.class)
    public RegisteredClientRepository registeredClientRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {

        OAuth2TokenSettings oauth2 = authContextProperties.getOauth2();
        String clientId = oauth2.getClientId();

        String clientSecret = requireConfiguredClientSecret(oauth2);

        String redirectUri = oauth2.getRedirectUri();
        String authorizedUri = oauth2.getAuthorizedUri();

        initializeAuthorizationServerSchema(jdbcTemplate.getDataSource());

        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(LibraryTableNames.wrap(jdbcTemplate));

        RegisteredClient existingClient = repository.findByClientId(clientId);
        if (existingClient != null) {
            rejectLegacyStoredClientSecret(existingClient.getClientSecret());
            rejectStoredClientSecretOtherThanConfigured(existingClient, clientSecret);
            synchronizeTokenSettings(repository, existingClient);
        }

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
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(false)
                            .requireProofKey(false)
                            .build())
                    .tokenSettings(configuredTokenSettings(TokenSettings.builder()));

            for (String scope : resolveConfiguredClientScopes(oauth2)) {
                builder.scope(scope);
            }

            if (StringUtils.hasText(redirectUri)) {
                builder.redirectUri(redirectUri);
            }
            if (StringUtils.hasText(authorizedUri)) {
                builder.redirectUri(authorizedUri);
            }

            RegisteredClient defaultClient = builder.build();

            transactionTemplate.executeWithoutResult(status -> {
                repository.save(defaultClient);
            });
        }

        return repository;
    }

    /**
     * The internal client is stored once, so its token lifetimes would otherwise keep the values of the first
     * start while the token cookies follow the current settings. Only the token settings derived from the
     * configuration are updated; the secret, grant types and scopes of the stored client stay as they are.
     */
    private void synchronizeTokenSettings(JdbcRegisteredClientRepository repository, RegisteredClient client) {
        TokenSettings stored = client.getTokenSettings();
        TokenSettings configured = configuredTokenSettings(TokenSettings.withSettings(stored.getSettings()));
        if (configured.getSettings().equals(stored.getSettings())) {
            return;
        }
        RegisteredClient updated = RegisteredClient.from(client).tokenSettings(configured).build();
        transactionTemplate.executeWithoutResult(status -> repository.save(updated));
    }

    private TokenSettings configuredTokenSettings(TokenSettings.Builder builder) {
        return builder
                .accessTokenTimeToLive(Duration.ofMillis(authContextProperties.getAccessTokenValidity()))
                .refreshTokenTimeToLive(Duration.ofMillis(authContextProperties.getRefreshTokenValidity()))
                .reuseRefreshTokens(false)
                .build();
    }

    private void initializeAuthorizationServerSchema(@Qualifier("contexaDataSource") DataSource dataSource) {
        if (dataSource == null) {
            throw new IllegalStateException("DataSource is required for OAuth2 authorization server schema initialization");
        }

        ResourceDatabasePopulator populator = new ResourceDatabasePopulator(
                new ClassPathResource("contexa-oauth2-authorization-schema.sql", IdentityOAuth2AutoConfiguration.class.getClassLoader()));
        populator.setContinueOnError(false);
        populator.execute(dataSource);
    }

    @Bean
    @ConditionalOnMissingBean(AuthorizationServerSettings.class)
    public AuthorizationServerSettings authorizationServerSettings() {
        OAuth2TokenSettings oauth2 = authContextProperties.getOauth2();
        String issuerUri = oauth2.getIssuerUri();

        AuthorizationServerSettings.Builder builder = AuthorizationServerSettings.builder()
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .jwkSetEndpoint("/oauth2/jwks")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .oidcClientRegistrationEndpoint("/connect/register")
                .oidcUserInfoEndpoint("/userinfo");

        if (StringUtils.hasText(issuerUri)) {
            builder.issuer(issuerUri);
        } else {
            log.info("[OAuth2] Issuer URI not configured (contexa.auth.oauth2.issuer-uri) - Spring Authorization Server will "
                    + "resolve the issuer from the current request for the internal token engine.");
        }

        return builder.build();
    }

    /*
     * No OAuth2TokenGenerator bean: the authorization server chain then builds Spring's generator, which applies Spring's
     * default claims (act for token exchange, cnf for DPoP and mutual TLS bound tokens) before the token customizer below.
     * An application that declares its own generator adds those claims itself; the chain puts Contexa's token checks in
     * front of it (CheckedTokenGenerator), since the server never offers a token to the customizer then.
     */

    /** What a person's token answers to at its renewal: the account as it is now, and the decision in force. */
    @Bean(name = "contexaAccountTokenGuard")
    @ConditionalOnMissingBean(AccountTokenGuard.class)
    public AccountTokenGuard accountTokenGuard(BeanFactory beanFactory,
                                               ObjectProvider<ZeroTrustActionRepository> zeroTrustActions) {
        return new AccountTokenGuard(() -> ContexaUserStore.of(beanFactory),
                () -> zeroTrustEnforcing() ? zeroTrustActions.getIfAvailable() : null);
    }

    /**
     * The token customizer the authorization server finds: Contexa's own checks first, then the application's customizers
     * (any number, in their order) that {@link HostTokenCustomizerDemotion} took out of the bean type the server looks for.
     * The server takes one customizer bean; before, a customizer of the application replaced Contexa's and its checks
     * with it.
     */
    @Bean(name = "contexaTokenCustomizer")
    @ConditionalOnMissingBean(name = "contexaTokenCustomizer")
    public ComposedTokenCustomizer composedTokenCustomizer(
            ObjectProvider<DelegationRegistry> delegationRegistry,
            ObjectProvider<AgentClientDirectory> agentClientDirectory,
            ObjectProvider<AccountTokenGuard> accountGuard,
            ObjectProvider<HostTokenCustomizer> applicationCustomizers) {
        return new ComposedTokenCustomizer(tokenCustomizer(delegationRegistry, agentClientDirectory, accountGuard),
                applicationCustomizers.orderedStream().toList());
    }

    /** Takes the application's token customizers out of the type the authorization server takes only one of. */
    @Bean(name = "contexaTokenCustomizerComposition")
    public static BeanFactoryPostProcessor tokenCustomizerComposition() {
        return new HostTokenCustomizerDemotion();
    }

    /** Contexa's own token checks and claims; the bean the server finds is {@link #composedTokenCustomizer}. */
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
            ObjectProvider<DelegationRegistry> delegationRegistry,
            ObjectProvider<AgentClientDirectory> agentClientDirectory,
            ObjectProvider<AccountTokenGuard> accountGuard) {

        return context -> {

            // docs/agent A5-3: a suspended agent gets no token, for itself or for a person.
            refuseSuspendedAgent(context, agentClientDirectory.getIfAvailable(),
                    authContextProperties.getOauth2().getClientId());

            UserDetails renewedAccount = renewedAccount(context, accountGuard.getIfAvailable());

            admitExchange(context, accountGuard.getIfAvailable());

            // docs/agent F-2: a delegation the person (or Contexa's stop) revoked ends the agent's exchange for them.
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                    && AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())) {
                try {
                    refuseRevokedDelegation(context, delegationRegistry.getIfAvailable(),
                            agentClientDirectory.getIfAvailable());
                } catch (OAuth2AuthenticationException refused) {
                    // docs/agent G-9: in the report-only mode the refusal of a revoked delegation is logged and the token is
                    // issued. A registry that cannot be read is no revoked delegation the operator chose to let through.
                    if (zeroTrustEnforcing() || OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE.equals(refused.getError().getErrorCode())) {
                        throw refused;
                    }
                    log.info("[ZeroTrust][SHADOW] An exchange under a revoked delegation goes on: client={}",
                            context.getRegisteredClient().getClientId());
                }
            }

            // docs/agent OC-1: a token an agent gets by token exchange for a person names the person's delegation.
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                    && AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())
                    && authContextProperties.getOauth2().isDelegationClaimEnabled()) {
                delegationClaim(context, delegationRegistry.getIfAvailable(), agentClientDirectory.getIfAvailable());
            }

            Object deviceId = context.get("device_id");
            if (deviceId != null) {
                context.getClaims().claim("device_id", deviceId);
            }

            // RFC 9068: an access token names the client it was issued to. A resource server then tells a client's
            // own token (client credentials, sub = client_id) from a person's token issued to the same client (A1-2).
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) && context.getRegisteredClient() != null) {
                context.getClaims().claim("client_id", context.getRegisteredClient().getClientId());
            }

            // The login facts of the authentication the token is issued for. The token engine hands the customizer
            // the grant and the authorization, not the values of its token context: an issued token reads them from
            // the internal login grant, a refreshed token from the authorization it came from (its login, not the
            // refresh time). Parameters of any other grant come from the client and are not login facts.
            Map<String, Object> grantParameters = context.getAuthorizationGrant()
                    instanceof AuthenticatedUserGrantAuthenticationToken loginGrant
                    && loginGrant.getAdditionalParameters() != null ? loginGrant.getAdditionalParameters() : Map.of();
            Map<String, Object> loginFacts = new HashMap<>();
            for (String name : LoginFactClaims.NAMES) {
                Object fact = grantParameters.get(name);
                if (fact == null && context.getAuthorization() != null) {
                    fact = context.getAuthorization().getAttribute(name);
                }
                if (fact != null) {
                    loginFacts.put(name, fact);
                }
            }
            LoginFactClaims.writeClaims(loginFacts, (name, value) -> context.getClaims().claim(name, value));

            List<String> roles = renewedAccount != null
                    ? AccountTokenGuard.rolesClaim(renewedAccount, context.getAuthorizedScopes())
                    : principalRoles(context.getPrincipal());
            if (!roles.isEmpty()) {
                context.getClaims().claim(AccountTokenGuard.ROLES_CLAIM, roles);
            }
        };
    }

    /**
     * The account a token being refreshed answers to, as it is now, or a refusal. Spring refreshes with the principal stored
     * at the sign-in, whatever became of the account since; null for a token of any other grant.
     */
    private static UserDetails renewedAccount(JwtEncodingContext context, AccountTokenGuard guard) {
        if (guard == null || context.getAuthorization() == null
                || !AuthorizationGrantType.REFRESH_TOKEN.equals(context.getAuthorizationGrantType())) {
            return null;
        }
        return guard.admitRenewal(context.getAuthorization().getPrincipalName());
    }

    /**
     * An exchange of a token for another client answers to the token it exchanges. It gets no scope that token does not
     * hold: Spring checks the scopes asked for against the client's only, and the token would speak for the person beyond
     * what the person's own token may do; {@code invalid_scope} is Spring's answer to a scope beyond what may be granted.
     * A person's token is exchanged by the rules of its renewal: not while a decision in force stops the person, not for an
     * account that is gone, disabled or locked.
     */
    static void admitExchange(JwtEncodingContext context, AccountTokenGuard guard) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                || !AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())) {
            return;
        }
        OAuth2Authorization subject = context.getAuthorization();
        if (subject == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        // An exchanged token is no subject: exchanged again it would outlive the sign-in it came from without end.
        if (AuthorizationGrantType.TOKEN_EXCHANGE.equals(subject.getAuthorizationGrantType())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
                    "A token issued by token exchange cannot be exchanged again", null));
        }
        OAuth2AccessToken subjectToken = subjectToken(context, subject);
        Set<String> subjectScopes = subjectToken != null ? subjectToken.getScopes() : subject.getAuthorizedScopes();
        if (!subjectScopes.containsAll(context.getAuthorizedScopes())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE,
                    "The scope asked for is beyond the scope of the token exchanged", null));
        }
        if (guard != null && isPersonsAuthorization(subject)) {
            guard.admitExchange(subject.getPrincipalName());
        }
        // The exchanged token ends no later than the token it exchanges.
        holdToLimit(context, subjectToken != null ? subjectToken.getExpiresAt() : null);
    }

    /**
     * The end of the token an exchange is issued for, which the exchanged token does not outlive; null for any other token
     * and for an exchange whose subject token tells no end.
     */
    static Instant exchangeLimit(JwtEncodingContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                || !AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())
                || context.getAuthorization() == null) {
            return null;
        }
        OAuth2AccessToken subjectToken = subjectToken(context, context.getAuthorization());
        return subjectToken != null ? subjectToken.getExpiresAt() : null;
    }

    /** Ends the token at the limit when it would end after it; a token that ends sooner is left as it is. */
    static void holdToLimit(JwtEncodingContext context, Instant limit) {
        if (limit == null) {
            return;
        }
        Instant expiresAt = context.getClaims().build().getExpiresAt();
        if (expiresAt == null || expiresAt.isAfter(limit)) {
            context.getClaims().expiresAt(limit);
        }
    }

    /** The token exchanged, as it was issued, or null when the authorization does not tell it. */
    private static OAuth2AccessToken subjectToken(JwtEncodingContext context, OAuth2Authorization subject) {
        if (context.getAuthorizationGrant() instanceof OAuth2TokenExchangeAuthenticationToken exchange
                && exchange.getSubjectToken() != null) {
            OAuth2Authorization.Token<OAuth2Token> token = subject.getToken(exchange.getSubjectToken());
            if (token != null && token.getToken() instanceof OAuth2AccessToken accessToken) {
                return accessToken;
            }
        }
        return null;
    }

    /** Whether an authorization is a person's sign-in rather than a client's own token. */
    private static boolean isPersonsAuthorization(OAuth2Authorization authorization) {
        return !AuthorizationGrantType.CLIENT_CREDENTIALS.equals(authorization.getAuthorizationGrantType())
                && !(authorization.getAttribute(Principal.class.getName()) instanceof OAuth2ClientAuthenticationToken);
    }

    private static List<String> principalRoles(Authentication principal) {
        if (principal == null || principal.getAuthorities() == null) {
            return List.of();
        }
        return principal.getAuthorities().stream()
                .map(grantedAuthority -> {
                    String auth = grantedAuthority.getAuthority();
                    return auth.startsWith("ROLE_") ? auth.substring(5) : auth;
                })
                .collect(Collectors.toList());
    }

    /** The claim naming the delegation a token exchanged for an agent runs under (the bridge reads it by default). */
    static final String DELEGATION_ID_CLAIM = "delegation_id";

    /**
     * docs/agent OC-1: names the delegation the person holds with the agent the client is, when one holds now. The
     * person is the exchange's subject; an agent that is not approved and in service gets no delegation.
     */
    /**
     * docs/agent A5-3: refuses to issue a token to a client that is a suspended agent. The token engine knows no tenant
     * of a client, so a suspension of the client in any tenant refuses it. When the suspension cannot be read, the token
     * waits as well ({@code temporarily_unavailable}, nothing of the cause in the answer): a failure of the store must not
     * lift a restriction. The internal client is the sign-in of a person and no agent, so its tokens never ask the directory.
     */
    static void refuseSuspendedAgent(JwtEncodingContext context, AgentClientDirectory agents, String internalClientId) {
        if (agents == null || context.getRegisteredClient() == null) {
            return;
        }
        String clientId = context.getRegisteredClient().getClientId();
        if (clientId == null || clientId.equals(internalClientId)) {
            return;
        }
        boolean suspended;
        try {
            suspended = agents.suspendedAgentClient(null, clientId);
        } catch (AgentClientStatusUnavailableException unreadable) {
            throw agentUnreadable();
        }
        if (suspended) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
                    "The agent is suspended", null));
        }
    }

    /**
     * What a token waits with while the agent registry cannot be read. No cause is attached: its text would become the
     * message of the exception. The registry says why in the log.
     */
    private static OAuth2AuthenticationException agentUnreadable() {
        return new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE,
                "The status of the agent cannot be read now", null));
    }

    /** Whether Contexa enforces its zero trust decisions (not the report-only SHADOW mode). */
    private boolean zeroTrustEnforcing() {
        SecurityZeroTrustProperties properties = zeroTrustProperties != null ? zeroTrustProperties.getIfAvailable()
                : null;
        return properties == null || properties.isEnforcementEnabled();
    }

    /**
     * docs/agent F-2: an agent exchanging a person's token gets none when the person's latest delegation to it was
     * revoked and none holds now. Without any delegation recorded the exchange goes on (OC-1); an expired one goes
     * on as well, and the agent's request then waits for the person's confirmation (A5-2).
     */
    static void refuseRevokedDelegation(JwtEncodingContext context, DelegationRegistry registry,
                                        AgentClientDirectory agents) {
        String person = exchangedPerson(context, registry, agents);
        if (person == null) {
            return;
        }
        String clientId = context.getRegisteredClient().getClientId();
        // A registry that cannot say which tenant and which agent the client is does not let the exchange through as one of
        // no agent: the person's revocation could not be found.
        String tenant;
        Optional<String> agent;
        try {
            tenant = agents.tenantOfClient(clientId).orElse(null);
            agent = agents.activeAgentForClient(tenant, clientId);
        } catch (AgentClientStatusUnavailableException unreadable) {
            throw agentUnreadable();
        }
        agent.ifPresent(agentId -> {
            Instant now = Instant.now();
            AgentDelegations.current(registry.list(tenant, person, agentId, DELEGATION_CANDIDATES), now)
                    .filter(delegation -> !delegation.validAt(now) && delegation.revokedAt() != null
                            && !delegation.revokedAt().isAfter(delegation.expiresAt()))
                    .ifPresent(revoked -> {
                        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
                                "The person's delegation to this agent was revoked", null));
                    });
        });
    }

    /** The person whose token the agent exchanges, or null when there is nothing to look up. */
    private static String exchangedPerson(JwtEncodingContext context, DelegationRegistry registry,
                                          AgentClientDirectory agents) {
        if (registry == null || agents == null || context.getRegisteredClient() == null
                || context.getPrincipal() == null) {
            return null;
        }
        Authentication principal = context.getPrincipal();
        String person = principal instanceof OAuth2TokenExchangeCompositeAuthenticationToken composite
                && composite.getSubject() != null ? composite.getSubject().getName() : principal.getName();
        return person == null || person.isBlank() ? null : person;
    }

    static void delegationClaim(JwtEncodingContext context, DelegationRegistry registry,
                                AgentClientDirectory agents) {
        if (registry == null || agents == null || context.getRegisteredClient() == null
                || context.getPrincipal() == null) {
            return;
        }
        Authentication principal = context.getPrincipal();
        String person = principal instanceof OAuth2TokenExchangeCompositeAuthenticationToken composite
                && composite.getSubject() != null ? composite.getSubject().getName() : principal.getName();
        if (person == null || person.isBlank()) {
            return;
        }
        String clientId = context.getRegisteredClient().getClientId();
        String tenant;
        Optional<String> agent;
        try {
            tenant = agents.tenantOfClient(clientId).orElse(null);
            agent = agents.activeAgentForClient(tenant, clientId);
        } catch (AgentClientStatusUnavailableException unreadable) {
            throw agentUnreadable();
        }
        agent.ifPresent(agentId -> {
            Instant now = Instant.now();
            AgentDelegations.current(registry.list(tenant, person, agentId, DELEGATION_CANDIDATES), now)
                    .filter(delegation -> delegation.validAt(now))
                    .ifPresent(delegation -> context.getClaims().claim(DELEGATION_ID_CLAIM,
                            delegation.delegationId()));
        });
    }

    /** The most of a person's delegations to one agent read when a token is exchanged. */
    private static final int DELEGATION_CANDIDATES = 50;

    @Bean(name = "contexaOauth2TokenValidator")
    @ConditionalOnMissingBean(TokenValidator.class)
    public TokenValidator oauth2TokenValidator(
            @Qualifier("contexaJwtDecoder") JwtDecoder jwtDecoder,
            OAuth2AuthorizationService contexaAuthorizationService) {

        long rotateThresholdMillis = authContextProperties.getRefreshTokenValidity() / 2;

        return new OAuth2TokenValidator(
                jwtDecoder,
                contexaAuthorizationService,
                rotateThresholdMillis);
    }

    @Bean(name = "contexaOauth2TokenService")
    @ConditionalOnMissingBean(TokenService.class)
    public TokenService oauth2TokenService(
            OAuth2AuthorizedClientManager contexaAuthorizedClientManager,
            ClientRegistrationRepository contexaClientRegistrationRepository,
            OAuth2AuthorizationService contexaAuthorizationService,
            TokenValidator contexaOauth2TokenValidator,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            ObjectProvider<ZeroTrustActionRepository> zeroTrustActionRepositoryProvider,
            ObjectProvider<AccountTokenGuard> accountGuard,
            RegisteredClientRepository registeredClientRepository) {

        TokenTransportStrategy transport = TokenTransportStrategyFactory.create(authContextProperties);

        OAuth2TokenService tokenService = new OAuth2TokenService(
                contexaAuthorizedClientManager,
                contexaClientRegistrationRepository,
                contexaAuthorizationService,
                contexaOauth2TokenValidator,
                authContextProperties,
                objectMapper,
                transport);
        tokenService.setZeroTrustActionRepository(zeroTrustActionRepositoryProvider.getIfAvailable());
        tokenService.setAccountGuard(accountGuard.getIfAvailable());
        tokenService.setRegisteredClients(registeredClientRepository);
        return tokenService;
    }

    @Bean("contexaOauth2TokenSuccessHandler")
    @ConditionalOnMissingBean(name = "contexaOauth2TokenSuccessHandler")
    public AuthenticationSuccessHandler oauth2TokenSuccessHandler() {
        return new OAuth2TokenSuccessHandler();
    }

    @Bean("contexaCompositeLogoutHandler")
    @ConditionalOnMissingBean(name = "contexaCompositeLogoutHandler")
    public CompositeLogoutHandler compositeLogoutHandler(
            TokenService tokenService,
            AuthContextProperties authContextProperties,
            ObjectProvider<ZeroTrustSecurityService> zeroTrustSecurityServiceProvider,
            SessionIdResolver sessionIdResolver,
            DeviceAwareOAuth2AuthorizationService authorizationService,
            ObjectProvider<MfaSessionRepository> mfaSessionRepository,
            ObjectProvider<MfaStateMachineService> mfaStateMachineService,
            RegisteredClientRepository registeredClientRepository,
            ObjectProvider<AgentClientDirectory> agentClientDirectory,
            ObjectProvider<DelegationRegistry> delegationRegistry) {

        ZeroTrustSecurityService zeroTrustService = zeroTrustSecurityServiceProvider.getIfAvailable();
        // A person's sign-out ends the tokens agents got by exchanging the person's tokens, unless a delegation governs them.
        ExchangedTokensOfASignOut exchangedTokens = new ExchangedTokensOfASignOut(authorizationService,
                registeredClientRepository, agentClientDirectory::getIfAvailable, delegationRegistry::getIfAvailable);

        List<LogoutStrategy> strategies = new ArrayList<>();
        strategies.add(new MfaFlowLogoutStrategy(mfaSessionRepository, mfaStateMachineService));
        strategies.add(new SessionLogoutStrategy(new HttpSessionCsrfTokenRepository(), authContextProperties));
        strategies.add(new OAuth2LogoutStrategy(tokenService, authorizationService, exchangedTokens));
        if (zeroTrustService != null) {
            strategies.add(new ZeroTrustLogoutStrategy(zeroTrustService, sessionIdResolver));
        }

        return new CompositeLogoutHandler(
                strategies,
                tokenService,
                zeroTrustService,
                authorizationService);
    }

    @Bean("contexaOauth2LogoutSuccessHandler")
    @ConditionalOnMissingBean(name = "contexaOauth2LogoutSuccessHandler")
    public LogoutSuccessHandler oauth2LogoutSuccessHandler(AuthResponseWriter responseWriter) {
        return new OAuth2LogoutSuccessHandler(responseWriter);
    }

    @Primary
    @Bean(name = "contexaClientRegistrationRepository")
    @ConditionalOnMissingBean(name = "contexaClientRegistrationRepository")
    public ClientRegistrationRepository clientRegistrationRepository(
            RegisteredClientRepository registeredClientRepository) {
        OAuth2TokenSettings oauth2 = authContextProperties.getOauth2();

        String registrationId = "aidc-internal";
        String clientId = oauth2.getClientId();
        String clientSecret = resolveClientRegistrationSecret(oauth2, registeredClientRepository);
        String tokenUri = resolveTokenUri(oauth2);

        String[] scopes = resolveConfiguredClientScopes(oauth2).toArray(String[]::new);

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

    private String requireConfiguredClientSecret(OAuth2TokenSettings oauth2) {
        String clientSecret = oauth2.getClientSecret();
        if (!usesOAuth2Issuance()) {
            if (StringUtils.hasText(clientSecret)) {
                return clientSecret;
            }
            synchronized (this) {
                if (unusedInternalClientSecret == null) {
                    unusedInternalClientSecret = UUID.randomUUID().toString();
                }
                return unusedInternalClientSecret;
            }
        }
        rejectLegacyClientSecret(clientSecret, "contexa.auth.oauth2.client-secret");
        if (!StringUtils.hasText(clientSecret)) {
            throw new IllegalStateException("[OAuth2] contexa.auth.oauth2.client-secret is required. "
                    + "Configure a unique client secret that remains available across restarts.");
        }
        return clientSecret;
    }

    private String resolveClientRegistrationSecret(
            OAuth2TokenSettings oauth2,
            RegisteredClientRepository registeredClientRepository) {

        String clientSecret = requireConfiguredClientSecret(oauth2);
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(oauth2.getClientId());
        if (registeredClient != null) {
            rejectLegacyStoredClientSecret(registeredClient.getClientSecret());
        }
        return clientSecret;
    }

    private void rejectLegacyStoredClientSecret(String clientSecret) {
        if (!usesOAuth2Issuance()) {
            return;
        }
        rejectLegacyClientSecret(clientSecret, "stored OAuth2 client");
        // Spring upgrades the auto-registered {noop} secret to {bcrypt} on authentication.
        if (clientSecret != null && clientSecret.startsWith("{bcrypt}")
                && PasswordEncoderFactories.createDelegatingPasswordEncoder()
                        .matches(LEGACY_DEFAULT_CLIENT_SECRET, clientSecret)) {
            rejectLegacyClientSecret(LEGACY_DEFAULT_CLIENT_SECRET, "stored OAuth2 client");
        }
    }

    /**
     * Contexa signs its own token requests with the configured secret, so the stored internal client must accept it.
     * A client stored before Contexa issued tokens (an application adding its first OAuth2 flow) keeps the secret it
     * was stored with, and every sign-in of an OAuth2 flow would then fail with invalid_client. As with the legacy
     * secret, the stored client is never rewritten silently: startup stops and says what to change. The check uses the
     * encoder Spring's client secret provider uses.
     */
    private void rejectStoredClientSecretOtherThanConfigured(RegisteredClient stored, String configuredSecret) {
        if (!usesOAuth2Issuance() || stored.getClientSecret() == null) {
            return;
        }
        boolean accepted;
        try {
            accepted = PasswordEncoderFactories.createDelegatingPasswordEncoder()
                    .matches(configuredSecret, stored.getClientSecret());
        } catch (IllegalArgumentException unreadableStoredSecret) {
            accepted = false;
        }
        if (!accepted) {
            throw new IllegalStateException("[OAuth2] The stored OAuth2 client '" + stored.getClientId()
                    + "' does not accept the configured contexa.auth.oauth2.client-secret, so Contexa could not "
                    + "issue tokens. Set the stored client's secret to the configured one, or remove the stored client "
                    + "so that it is registered again, before starting the authorization server.");
        }
    }

    private boolean usesOAuth2Issuance() {
        if (authContextProperties.getOauth2ServerMode() != null
                && !authContextProperties.getOauth2ServerMode().includesAuthorizationServer()) {
            return false;
        }
        PlatformConfig platformConfig = platformConfigProvider != null ? platformConfigProvider.getIfAvailable() : null;
        if (platformConfig == null || platformConfig.getFlows().isEmpty()) {
            return authContextProperties.getStateType() == StateType.OAUTH2;
        }
        return platformConfig.getFlows().stream().anyMatch(flow -> {
            StateType stateType = flow.getStateConfig() != null ? flow.getStateConfig().stateType() : null;
            return (stateType != null ? stateType : authContextProperties.getStateType()) == StateType.OAUTH2;
        });
    }

    private void rejectLegacyClientSecret(String clientSecret, String source) {
        if (LEGACY_DEFAULT_CLIENT_SECRET.equals(clientSecret)
                || (NOOP_SECRET_PREFIX + LEGACY_DEFAULT_CLIENT_SECRET).equals(clientSecret)) {
            throw new IllegalStateException("[OAuth2] The known legacy default client secret is not allowed in "
                    + source + ". Replace the stored client secret and configure the matching unique "
                    + "contexa.auth.oauth2.client-secret before starting the authorization server.");
        }
    }

    private String resolveTokenUri(OAuth2TokenSettings oauth2) {
        String tokenEndpoint = StringUtils.hasText(oauth2.getTokenEndpoint())
                ? oauth2.getTokenEndpoint()
                : "/oauth2/token";
        String issuerUri = oauth2.getIssuerUri();
        if (StringUtils.hasText(issuerUri)) {
            return issuerUri + tokenEndpoint;
        }
        return tokenEndpoint;
    }

    private Set<String> resolveConfiguredClientScopes(OAuth2TokenSettings oauth2) {
        String configuredScopes = oauth2.getScope();
        if (!StringUtils.hasText(configuredScopes)) {
            return Set.of(DEFAULT_SCOPE);
        }
        Set<String> scopes = Arrays.stream(configuredScopes.trim().split("[,\\s]+"))
                .filter(StringUtils::hasText)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return scopes.isEmpty() ? Set.of(DEFAULT_SCOPE) : scopes;
    }

    @Primary
    @Bean(name = "contexaAuthorizedClientRepository")
    @ConditionalOnMissingBean(name = "contexaAuthorizedClientRepository")
    public OAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Primary
    @Bean(name = "contexaAuthorizedClientManager")
    @ConditionalOnMissingBean(name = "contexaAuthorizedClientManager")
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository contexaClientRegistrationRepository,
            ObjectProvider<FilterChainProxy> filterChainProxyProvider,
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService contexaAuthorizationService) {

        InProcessOAuth2TokenEndpoint tokenEndpoint = new InProcessOAuth2TokenEndpoint(
                filterChainProxyProvider,
                new ClientSecretBasicAuthenticationConverter(),
                new ClientSecretAuthenticationProvider(registeredClientRepository, contexaAuthorizationService));

        AuthenticatedUserOAuth2AuthorizedClientProvider authenticatedUserProvider =
                new AuthenticatedUserOAuth2AuthorizedClientProvider(
                        new InProcessAuthenticatedUserTokenResponseClient(tokenEndpoint));

        OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
                .provider(authenticatedUserProvider)
                .refreshToken(refreshToken -> refreshToken
                        .accessTokenResponseClient(new InProcessRefreshTokenTokenResponseClient(tokenEndpoint)))
                .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
                contexaClientRegistrationRepository,
                new TransientOAuth2AuthorizedClientRepository());

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
            for (String name : LoginFactClaims.NAMES) {
                Object fact = authorizeRequest.getAttribute(name);
                if (fact != null) {
                    contextAttributes.put(name, fact);
                }
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
