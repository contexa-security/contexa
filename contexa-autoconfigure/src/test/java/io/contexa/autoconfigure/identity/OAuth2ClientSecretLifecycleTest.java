/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.contexa.autoconfigure.identity;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.OAuth2ServerMode;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationProvider;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuth2ClientSecretLifecycleTest {

    private static final String LEGACY_SECRET = "173f8245-5f7d-4623-a612-aa0c68f6da4a";
    private static final String CONFIGURED_SECRET = "lifecycle-test-unique-client-secret";

    private JdbcTemplate jdbcTemplate;
    private TransactionTemplate transactionTemplate;

    @BeforeEach
    void setUp() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        jdbcTemplate = new JdbcTemplate(dataSource);
        transactionTemplate = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
    }

    @AfterEach
    void tearDown() {
        AuthorizationServerContextHolder.resetContext();
        jdbcTemplate.execute("SHUTDOWN");
    }

    @Test
    void freshAndRestartedClientsRejectLegacySecretAndIssueValidUserTokens() {
        AuthContextProperties properties = properties(true);
        assertThat(new AuthContextProperties().getOauth2().getClientSecret()).isNull();
        IdentityOAuth2AutoConfiguration first = configuration(properties);
        RegisteredClientRepository firstRepository = first.registeredClientRepository(jdbcTemplate);
        ClientRegistration firstClient = internalClient(first, firstRepository);
        RegisteredClient stored = firstRepository.findByClientId(firstClient.getClientId());

        assertThat(firstClient.getClientSecret()).isNotBlank().isNotEqualTo(LEGACY_SECRET);
        assertThat(stored.getClientSecret()).isEqualTo("{noop}" + firstClient.getClientSecret());
        assertThat(firstClient.getClientSecret()).isEqualTo(CONFIGURED_SECRET);
        assertRejectedSecret(firstRepository, firstClient.getClientId(), LEGACY_SECRET);
        assertUserTokenIssued(first, firstRepository, firstClient);

        assertThat(firstRepository.findByClientId(firstClient.getClientId()).getClientSecret()).startsWith("{bcrypt}");
        IdentityOAuth2AutoConfiguration restarted = configuration(properties(true));
        RegisteredClientRepository restartedRepository = restarted.registeredClientRepository(jdbcTemplate);
        ClientRegistration restartedClient = internalClient(restarted, restartedRepository);

        assertThat(restartedClient.getClientSecret()).isEqualTo(firstClient.getClientSecret());
        assertThat(restartedRepository.findByClientId(firstClient.getClientId()).getId()).isEqualTo(stored.getId());
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM oauth2_registered_client", Integer.class))
                .isEqualTo(1);
        assertRejectedSecret(restartedRepository, restartedClient.getClientId(), LEGACY_SECRET);
        assertUserTokenIssued(restarted, restartedRepository, restartedClient);
    }

    @Test
    void missingSecretPreventsFreshInstallationFromServingTokens() {
        IdentityOAuth2AutoConfiguration configuration = configuration(properties(false));
        assertThatThrownBy(() -> configuration.registeredClientRepository(jdbcTemplate))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contexa.auth.oauth2.client-secret is required");
    }

    @Test
    void sessionOnlyDslDoesNotRequireAnUnusedOAuth2Secret() {
        AuthContextProperties properties = properties(false);
        PlatformConfig platform = PlatformConfig.builder().addFlow(AuthenticationFlowConfig.builder("form")
                .stepConfigs(List.of(new AuthenticationStepConfig("FORM", 0)))
                .stateConfig(new StateConfig("session", StateType.SESSION)).build()).build();
        IdentityOAuth2AutoConfiguration configuration = configuration(properties, platform);

        RegisteredClientRepository repository = configuration.registeredClientRepository(jdbcTemplate);
        assertThat(internalClient(configuration, repository)).isNotNull();
    }

    @Test
    void resourceServerOnlyDoesNotRequireAnIssuingClientSecret() {
        AuthContextProperties properties = properties(false);
        properties.setOauth2ServerMode(OAuth2ServerMode.RESOURCE_SERVER);
        IdentityOAuth2AutoConfiguration configuration = configuration(properties);

        RegisteredClientRepository repository = configuration.registeredClientRepository(jdbcTemplate);
        assertThat(internalClient(configuration, repository)).isNotNull();
    }

    @Test
    void oauth2DslStillRequiresSecretWhenDefaultStateIsSession() {
        AuthContextProperties properties = properties(false);
        properties.setStateType(StateType.SESSION);
        PlatformConfig platform = PlatformConfig.builder().addFlow(AuthenticationFlowConfig.builder("rest")
                .stepConfigs(List.of(new AuthenticationStepConfig("REST", 0)))
                .stateConfig(new StateConfig("oauth2", StateType.OAUTH2)).build()).build();

        assertThatThrownBy(() -> configuration(properties, platform).registeredClientRepository(jdbcTemplate))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contexa.auth.oauth2.client-secret is required");
    }

    @ParameterizedTest
    @ValueSource(strings = {LEGACY_SECRET, "{noop}" + LEGACY_SECRET})
    void explicitlyConfiguredLegacySecretIsRejected(String secret) {
        AuthContextProperties properties = properties(false);
        properties.getOauth2().setClientSecret(secret);
        IdentityOAuth2AutoConfiguration configuration = configuration(properties);

        assertThatThrownBy(() -> configuration.registeredClientRepository(jdbcTemplate))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("known legacy default client secret")
                .hasMessageContaining("contexa.auth.oauth2.client-secret")
                .hasMessageNotContaining(LEGACY_SECRET);
        assertThatThrownBy(() -> configuration.clientRegistrationRepository(mock(RegisteredClientRepository.class)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("known legacy default client secret");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void legacyDatabaseClientPreventsStartupEvenWithNewConfiguredSecret(boolean upgraded) {
        RegisteredClientRepository original = seedClient("{noop}" + LEGACY_SECRET);
        if (upgraded) {
            new ClientSecretAuthenticationProvider(original, new InMemoryOAuth2AuthorizationService())
                    .authenticate(clientRequest("default-client", LEGACY_SECRET));
            assertThat(original.findByClientId("default-client").getClientSecret()).startsWith("{bcrypt}");
        }
        String originalSecret = original.findByClientId("default-client").getClientSecret();
        IdentityOAuth2AutoConfiguration configuration = configuration(properties(true));

        assertThatThrownBy(() -> configuration.registeredClientRepository(jdbcTemplate))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("stored OAuth2 client")
                .hasMessageNotContaining(LEGACY_SECRET);
        assertThatThrownBy(() -> configuration.clientRegistrationRepository(original))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("stored OAuth2 client");
        assertThat(original.findByClientId("default-client").getClientSecret())
                .as("startup rejection must not silently rewrite an existing client")
                .isEqualTo(originalSecret);
    }

    @Test
    void replacingOnlyLegacyClientSecretRestoresNormalIssuance() {
        RegisteredClientRepository repository = seedClient("{noop}" + LEGACY_SECRET);
        RegisteredClient oldClient = repository.findByClientId("default-client");
        repository.save(RegisteredClient.from(oldClient).clientSecret("{noop}" + CONFIGURED_SECRET).build());
        IdentityOAuth2AutoConfiguration configuration = configuration(properties(true));

        RegisteredClientRepository updated = configuration.registeredClientRepository(jdbcTemplate);
        RegisteredClient stored = updated.findByClientId("default-client");
        assertThat(stored.getId()).isEqualTo(oldClient.getId());
        assertThat(stored.getAuthorizationGrantTypes()).isEqualTo(oldClient.getAuthorizationGrantTypes());
        assertThat(stored.getScopes()).isEqualTo(oldClient.getScopes());
        assertRejectedSecret(updated, stored.getClientId(), LEGACY_SECRET);
        assertUserTokenIssued(configuration, updated, internalClient(configuration, updated));
    }

    @Test
    void restartWithChangedTokenValidityUpdatesOnlyTheStoredTokenSettings() {
        AuthContextProperties first = properties(true);
        configuration(first).registeredClientRepository(jdbcTemplate);
        RegisteredClient stored = new JdbcRegisteredClientRepository(jdbcTemplate).findByClientId("default-client");
        assertThat(stored.getTokenSettings().getAccessTokenTimeToLive())
                .isEqualTo(Duration.ofMillis(first.getAccessTokenValidity()));

        AuthContextProperties changed = properties(true);
        changed.setAccessTokenValidity(Duration.ofSeconds(90).toMillis());
        changed.setRefreshTokenValidity(Duration.ofHours(2).toMillis());
        RegisteredClient updated = configuration(changed).registeredClientRepository(jdbcTemplate)
                .findByClientId("default-client");

        assertThat(updated.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofSeconds(90));
        assertThat(updated.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofHours(2));
        assertThat(updated.getTokenSettings().isReuseRefreshTokens()).isFalse();
        assertThat(updated.getId()).isEqualTo(stored.getId());
        assertThat(updated.getClientSecret()).isEqualTo(stored.getClientSecret());
        assertThat(updated.getAuthorizationGrantTypes()).isEqualTo(stored.getAuthorizationGrantTypes());
        assertThat(updated.getScopes()).isEqualTo(stored.getScopes());
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM oauth2_registered_client", Integer.class))
                .isEqualTo(1);
    }

    private AuthContextProperties properties(boolean configured) {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setIssuerUri("https://issuer.example.test");
        if (configured) {
            properties.getOauth2().setClientSecret(CONFIGURED_SECRET);
        }
        return properties;
    }

    private IdentityOAuth2AutoConfiguration configuration(AuthContextProperties properties) {
        return new IdentityOAuth2AutoConfiguration(transactionTemplate, properties);
    }

    private IdentityOAuth2AutoConfiguration configuration(AuthContextProperties properties, PlatformConfig platform) {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("platformConfig", platform);
        return new IdentityOAuth2AutoConfiguration(transactionTemplate, properties, beans.getBeanProvider(PlatformConfig.class));
    }

    private ClientRegistration internalClient(IdentityOAuth2AutoConfiguration configuration,
                                              RegisteredClientRepository repository) {
        return configuration.clientRegistrationRepository(repository).findByRegistrationId("aidc-internal");
    }

    private RegisteredClientRepository seedClient(String secret) {
        new ResourceDatabasePopulator(new ClassPathResource("contexa-oauth2-authorization-schema.sql"))
                .execute(jdbcTemplate.getDataSource());
        RegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);
        repository.save(RegisteredClient.withId("existing-client-id")
                .clientId("default-client")
                .clientSecret(secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("read")
                .build());
        return repository;
    }

    private void assertRejectedSecret(RegisteredClientRepository repository, String clientId, String secret) {
        ClientSecretAuthenticationProvider provider = new ClientSecretAuthenticationProvider(
                repository, new InMemoryOAuth2AuthorizationService());
        assertThatThrownBy(() -> provider.authenticate(clientRequest(clientId, secret)))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class,
                        exception -> assertThat(exception.getError().getErrorCode()).isEqualTo("invalid_client"));
    }

    private OAuth2ClientAuthenticationToken clientRequest(String clientId, String secret) {
        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                secret, Map.of("grant_type", AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER.getValue()));
    }

    private void assertUserTokenIssued(IdentityOAuth2AutoConfiguration configuration,
                                       RegisteredClientRepository repository, ClientRegistration registration) {
        InMemoryOAuth2AuthorizationService authorizations = new InMemoryOAuth2AuthorizationService();
        ClientSecretAuthenticationProvider clientProvider = new ClientSecretAuthenticationProvider(repository, authorizations);
        OAuth2ClientAuthenticationToken client = (OAuth2ClientAuthenticationToken) clientProvider.authenticate(
                clientRequest(registration.getClientId(), registration.getClientSecret()));
        assertThat(client.isAuthenticated()).isTrue();

        UserRepository users = mock(UserRepository.class);
        Users user = mock(Users.class);
        when(user.getUsername()).thenReturn("verified-user");
        when(user.getRoleNames()).thenReturn(List.of("ROLE_USER"));
        when(users.findByUsernameWithGroupsRolesAndPermissions("verified-user")).thenReturn(Optional.of(user));
        AuthorizationServerContext serverContext = mock(AuthorizationServerContext.class);
        when(serverContext.getIssuer()).thenReturn("https://issuer.example.test");
        when(serverContext.getAuthorizationServerSettings()).thenReturn(configuration.authorizationServerSettings());
        AuthorizationServerContextHolder.setContext(serverContext);

        JWKSource<SecurityContext> keys = configuration.jwkSource();
        JwtGenerator jwtGenerator = new JwtGenerator(configuration.jwtEncoder(keys));
        jwtGenerator.setJwtCustomizer(configuration.tokenCustomizer());
        AuthenticatedUserGrantAuthenticationProvider provider = new AuthenticatedUserGrantAuthenticationProvider(
                authorizations, new DelegatingOAuth2TokenGenerator(jwtGenerator, new OAuth2RefreshTokenGenerator()),
                users, transactionTemplate);
        OAuth2AccessTokenAuthenticationToken result = (OAuth2AccessTokenAuthenticationToken) provider.authenticate(
                new AuthenticatedUserGrantAuthenticationToken(client, "verified-user", null, Map.of()));

        Jwt jwt = configuration.jwtDecoder(keys).decode(result.getAccessToken().getTokenValue());
        assertThat(jwt.getSubject()).isEqualTo("verified-user");
        assertThat(jwt.getClaimAsStringList("roles")).contains("USER");
        assertThat(result.getRefreshToken()).isNotNull();
        assertThat(authorizations.findByToken(result.getAccessToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN))
                .isNotNull();
    }
}
