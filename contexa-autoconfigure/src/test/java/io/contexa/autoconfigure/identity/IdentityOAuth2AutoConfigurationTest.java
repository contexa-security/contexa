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

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.support.TransactionTemplate;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.Duration;
import java.time.Clock;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdentityOAuth2AutoConfigurationTest {

    @Test
    @DisplayName("Missing authorization server should not break a dependency-only application context")
    void missingAuthorizationServerDoesNotBreakDependencyOnlyContext() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(IdentityOAuth2AutoConfiguration.class))
                .withClassLoader(new FilteredClassLoader(
                        "org.springframework.security.oauth2.server.authorization"))
                .run(context -> assertThat(context.getStartupFailure()).isNull());
    }

    @Test
    @DisplayName("JWK fallback should be allowed for the internal token engine")
    void jwkFallbackAllowedForInternalTokenEngine() {
        IdentityOAuth2AutoConfiguration configuration = configuration(new AuthContextProperties());

        JWKSource<SecurityContext> jwkSource = configuration.jwkSource();

        assertThat(jwkSource).isNotNull();
    }

    @Test
    @DisplayName("Blank issuer should not fail internal authorization server settings")
    void blankIssuerDoesNotFailInternalAuthorizationServerSettings() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setIssuerUri("");
        IdentityOAuth2AutoConfiguration configuration = configuration(properties);

        AuthorizationServerSettings settings = configuration.authorizationServerSettings();

        assertThat(settings.getTokenEndpoint()).isEqualTo("/oauth2/token");
        assertThat(settings.getIssuer()).isNull();
    }

    @Test
    @DisplayName("Internal client registration should preserve the configured unique secret and scopes")
    void clientRegistrationUsesConfiguredUniqueSecret() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret("existing-secret");
        properties.getOauth2().setScope("read,write");

        IdentityOAuth2AutoConfiguration configuration = configuration(properties);

        RegisteredClientRepository registeredClientRepository = mock(RegisteredClientRepository.class);
        RegisteredClient registeredClient = RegisteredClient.withId("registered-client-id")
                .clientId(properties.getOauth2().getClientId())
                .clientSecret("{noop}existing-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .build();
        when(registeredClientRepository.findByClientId(properties.getOauth2().getClientId()))
                .thenReturn(registeredClient);

        ClientRegistrationRepository repository =
                configuration.clientRegistrationRepository(registeredClientRepository);

        ClientRegistration registration = repository.findByRegistrationId("aidc-internal");
        assertThat(registration.getClientSecret()).isEqualTo("existing-secret");
        assertThat(registration.getScopes()).containsExactlyInAnyOrder("read", "write");
    }

    @Test
    @DisplayName("Internal client registration requires a persistent configured secret")
    void clientRegistrationRejectsMissingSecret() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret("");
        IdentityOAuth2AutoConfiguration configuration = configuration(properties);

        RegisteredClientRepository registeredClientRepository = mock(RegisteredClientRepository.class);
        assertThatThrownBy(() -> configuration.clientRegistrationRepository(registeredClientRepository))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contexa.auth.oauth2.client-secret is required");
    }

    @Test
    @DisplayName("The signing key can be read from a key store file outside the classpath")
    void jwkKeyStoreFromFile(@TempDir Path tempDir) throws Exception {
        Path keyStore = tempDir.resolve("jwk.p12");
        Process keytool = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "contexa-jwk", "-keyalg", "RSA", "-keysize", "2048",
                "-storetype", "PKCS12", "-keystore", keyStore.toString(),
                "-storepass", "test-store-pass", "-keypass", "test-store-pass",
                "-dname", "CN=contexa-test", "-validity", "1")
                .redirectErrorStream(true)
                .start();
        assertThat(keytool.waitFor()).isZero();

        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setJwkKeyStorePath("file:" + keyStore.toAbsolutePath());
        properties.getOauth2().setJwkKeyStorePassword("test-store-pass");
        properties.getOauth2().setJwkKeyAlias("contexa-jwk");

        JWKSource<SecurityContext> jwkSource = configuration(properties).jwkSource();

        List<JWK> keys = jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
        assertThat(keys).singleElement().satisfies(key -> {
            assertThat(key.getKeyID()).isEqualTo("contexa-jwk");
            assertThat(key.isPrivate()).isTrue();
        });
    }

    @Test
    @DisplayName("A missing key store fails fast")
    void missingJwkKeyStoreFails() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setJwkKeyStorePath("file:/nonexistent/contexa-jwk.p12");

        assertThatThrownBy(() -> configuration(properties).jwkSource())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to load JWK from KeyStore");
    }

    @Test
    @DisplayName("The token customizer writes the login facts of the login grant, and a refreshed token keeps them")
    void tokenCustomizerWritesTheLoginFacts() {
        OAuth2TokenCustomizer<JwtEncodingContext> customizer =
                configuration(new AuthContextProperties()).tokenCustomizer(none(), none());

        JwtClaimsSet.Builder issuedClaims = JwtClaimsSet.builder().subject("alice");
        customizer.customize(JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256), issuedClaims)
                .authorizationGrant(new AuthenticatedUserGrantAuthenticationToken(mock(Authentication.class), "alice",
                        null, Map.of("auth_time", "1711276200", "amr", "pwd otp mfa", "acr", "AAL2",
                        "sid", "6c1f6b9e-1d2a-4c55-9b7e-0a8d5c3e2f10")))
                .build());

        assertThat(issuedClaims.build().getClaims())
                .containsEntry("auth_time", Date.from(Instant.ofEpochSecond(1711276200L)))
                .containsEntry("amr", List.of("pwd", "otp", "mfa"))
                .containsEntry("acr", "AAL2")
                .containsEntry("sid", "6c1f6b9e-1d2a-4c55-9b7e-0a8d5c3e2f10");

        RegisteredClient client = RegisteredClient.withId("client-1")
                .clientId("client-1")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .attribute("auth_time", "1711276200")
                .attribute("amr", "pwd otp mfa")
                .attribute("acr", "AAL2")
                .attribute("sid", "6c1f6b9e-1d2a-4c55-9b7e-0a8d5c3e2f10")
                .build();
        // A refresh request's own parameters come from the client: a claimed auth_time there is not a login fact.
        JwtClaimsSet.Builder refreshedClaims = JwtClaimsSet.builder().subject("alice");
        customizer.customize(JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256), refreshedClaims)
                .authorization(authorization)
                .authorizationGrant(new OAuth2RefreshTokenAuthenticationToken("refresh-token", mock(Authentication.class),
                        Set.of(), Map.of("auth_time", "1999999999", "sid", "forged-session")))
                .build());

        assertThat(refreshedClaims.build().getClaims())
                .containsEntry("auth_time", Date.from(Instant.ofEpochSecond(1711276200L)))
                .containsEntry("acr", "AAL2")
                .containsEntry("sid", "6c1f6b9e-1d2a-4c55-9b7e-0a8d5c3e2f10");
    }

    @Test
    @DisplayName("An access token names the client it was issued to (RFC 9068), so a client's own token is told from a person's (A1-2)")
    void accessTokenNamesTheClientItWasIssuedTo() throws Exception {
        IdentityOAuth2AutoConfiguration configuration = configuration(new AuthContextProperties());
        JwtGenerator generator = new JwtGenerator(new NimbusJwtEncoder(configuration.jwkSource()));
        generator.setJwtCustomizer(configuration.tokenCustomizer(none(), none()));
        RegisteredClient client = RegisteredClient.withId("report-service")
                .clientId("report-service")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        AuthorizationServerContext serverContext = new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return "https://issuer.test";
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return AuthorizationServerSettings.builder().build();
            }
        };

        Jwt token = generator.generate(DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .authorizationServerContext(serverContext)
                .principal(new UsernamePasswordAuthenticationToken("report-service", null, List.of()))
                .authorizedScopes(Set.of("reports.read"))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build());

        assertThat(token.getClaims())
                .containsEntry("client_id", "report-service")
                .containsEntry("sub", "report-service");

        // An ID token describes the person who signed in; it gets no client_id claim.
        JwtClaimsSet.Builder idTokenClaims = JwtClaimsSet.builder().subject("alice");
        configuration.tokenCustomizer(none(), none()).customize(JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256), idTokenClaims)
                .registeredClient(client)
                .tokenType(new OAuth2TokenType("id_token"))
                .build());
        assertThat(idTokenClaims.build().getClaims()).doesNotContainKey("client_id");
    }

    @Test
    @DisplayName("A token the real token engine issues carries the login facts, and its stored claims read back")
    void issuedTokenClaimsReadBackFromTheStoredAuthorization() throws Exception {
        IdentityOAuth2AutoConfiguration configuration = configuration(new AuthContextProperties());
        JwtGenerator generator = new JwtGenerator(new NimbusJwtEncoder(configuration.jwkSource()));
        generator.setJwtCustomizer(configuration.tokenCustomizer(none(), none()));
        RegisteredClient client = RegisteredClient.withId("client-1")
                .clientId("client-1")
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .build();
        AuthorizationServerContext serverContext = new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return "https://issuer.test";
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return AuthorizationServerSettings.builder().build();
            }
        };
        Jwt token = generator.generate(DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .authorizationServerContext(serverContext)
                .principal(new UsernamePasswordAuthenticationToken("alice", null, List.of()))
                .authorizedScopes(Set.of())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .authorizationGrant(new AuthenticatedUserGrantAuthenticationToken(mock(Authentication.class), "alice",
                        null, Map.of("auth_time", "1711276200", "amr", "pwd otp", "acr", "AAL2",
                        "sid", "6c1f6b9e-1d2a-4c55-9b7e-0a8d5c3e2f10", "principalType", "HUMAN_USER",
                        "mfaCompleted", "true", "challengeVerifiedAt", "2026-10-10T09:55:38.126512300Z")))
                .build());

        assertThat(token).isNotNull();
        assertThat(token.getClaims()).containsKeys("auth_time", "amr", "acr", "sid", "principalType", "mfaCompleted",
                "challengeVerifiedAt");

        // The authorization service writes the access token metadata (the token's claims) and reads it back with the
        // same mapper; the metadata is built as the grant provider builds it.
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName("alice")
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token.getTokenValue(),
                                token.getIssuedAt(), token.getExpiresAt()),
                        metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, token.getClaims()))
                .build();
        ObjectMapper mapper = configuration.authorizationObjectMapper();
        String stored = mapper.writeValueAsString(authorization.getAccessToken().getMetadata());
        Map<String, Object> read = mapper.readValue(stored, new TypeReference<Map<String, Object>>() {
        });
        Map<?, ?> claims = (Map<?, ?>) read.get(OAuth2Authorization.Token.CLAIMS_METADATA_NAME);
        assertThat(claims.get("auth_time")).isEqualTo(Date.from(Instant.ofEpochSecond(1711276200L)));
        assertThat(claims.get("acr")).isEqualTo("AAL2");
        assertThat(claims.get("sid")).isEqualTo("6c1f6b9e-1d2a-4c55-9b7e-0a8d5c3e2f10");
        assertThat(claims.get("principalType")).isEqualTo("HUMAN_USER");
        assertThat(claims.get("mfaCompleted")).isEqualTo(Boolean.TRUE);
        assertThat(claims.get("challengeVerifiedAt")).isEqualTo("2026-10-10T09:55:38.126512300Z");
    }

    @Test
    @DisplayName("docs/agent A5-3: a suspended agent's client gets no token, for itself or for a person; another client does")
    @SuppressWarnings("unchecked")
    void aSuspendedAgentsClientGetsNoToken() {
        AgentClientDirectory directory = new AgentClientDirectory() {
            @Override
            public Optional<String> activeAgentForClient(String tenantId, String clientId) {
                return Optional.empty();
            }

            @Override
            public boolean suspendedAgentClient(String tenantId, String clientId) {
                return "sync-client".equals(clientId);
            }
        };
        ObjectProvider<AgentClientDirectory> agents = mock(ObjectProvider.class);
        when(agents.getIfAvailable()).thenReturn(directory);
        OAuth2TokenCustomizer<JwtEncodingContext> customizer =
                configuration(new AuthContextProperties()).tokenCustomizer(none(), agents);

        assertThatThrownBy(() -> customizer.customize(accessTokenContext("sync-client")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(e -> assertThat(((OAuth2AuthenticationException) e).getError().getErrorCode())
                        .isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
        JwtEncodingContext other = accessTokenContext("report-client");
        customizer.customize(other);
        assertThat(other.getClaims().build().getClaims()).containsEntry("client_id", "report-client");
    }

    @Test
    @DisplayName("docs/agent F-2: an agent gets no exchanged token for a person who revoked the delegation; an expired or absent one goes on")
    @SuppressWarnings("unchecked")
    void anExchangeForARevokedDelegationIsRefused() {
        AgentClientDirectory directory = (tenantId, clientId) -> "report-client".equals(clientId)
                ? Optional.of("report-agent") : Optional.empty();
        ObjectProvider<AgentClientDirectory> agents = mock(ObjectProvider.class);
        when(agents.getIfAvailable()).thenReturn(directory);
        InMemoryDelegationRegistry registry = new InMemoryDelegationRegistry();
        ObjectProvider<DelegationRegistry> delegations = mock(ObjectProvider.class);
        when(delegations.getIfAvailable()).thenReturn(registry);
        OAuth2TokenCustomizer<JwtEncodingContext> customizer =
                configuration(new AuthContextProperties()).tokenCustomizer(delegations, agents);

        // No delegation recorded: the exchange goes on (OC-1).
        customizer.customize(exchangeContext("alice"));

        AgentDelegation revoked = registry.record(new AgentDelegationRequest(null, "alice", "report-agent", null,
                "REPORTING", "Weekly report", List.of("READ"), List.of(), null, null, null,
                Instant.now().minusSeconds(3600), Instant.now().plusSeconds(3600), null, null));
        registry.revoke(revoked.delegationId(), "alice", "done");
        assertThatThrownBy(() -> customizer.customize(exchangeContext("alice")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(e -> assertThat(((OAuth2AuthenticationException) e).getError().getErrorCode())
                        .isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));
        // Another person's exchange is not touched.
        customizer.customize(exchangeContext("bob"));

        // An expired delegation goes on; the agent's request then waits for the person (A5-2).
        InMemoryDelegationRegistry earlier = new InMemoryDelegationRegistry(Duration.ofDays(30),
                Clock.fixed(Instant.now().minus(Duration.ofDays(2)), ZoneOffset.UTC));
        earlier.record(new AgentDelegationRequest(null, "carol", "report-agent", null, "REPORTING", "Weekly report",
                List.of("READ"), List.of(), null, null, null, Instant.now().minus(Duration.ofDays(2)),
                Instant.now().minusSeconds(3600), null, null));
        ObjectProvider<DelegationRegistry> expired = mock(ObjectProvider.class);
        when(expired.getIfAvailable()).thenReturn(earlier);
        configuration(new AuthContextProperties()).tokenCustomizer(expired, agents)
                .customize(exchangeContext("carol"));
    }

    @Test
    @DisplayName("docs/agent G-9: in the report-only mode an exchange under a revoked delegation is logged and issued")
    @SuppressWarnings("unchecked")
    void inTheReportOnlyModeAnExchangeUnderARevokedDelegationGoesOn() {
        AgentClientDirectory directory = (tenantId, clientId) -> Optional.of("report-agent");
        ObjectProvider<AgentClientDirectory> agents = mock(ObjectProvider.class);
        when(agents.getIfAvailable()).thenReturn(directory);
        InMemoryDelegationRegistry registry = new InMemoryDelegationRegistry();
        AgentDelegation revoked = registry.record(new AgentDelegationRequest(null, "alice", "report-agent", null,
                "REPORTING", "Weekly report", List.of("READ"), List.of(), null, null, null,
                Instant.now().minusSeconds(3600), Instant.now().plusSeconds(3600), null, null));
        registry.revoke(revoked.delegationId(), "alice", "done");
        ObjectProvider<DelegationRegistry> delegations = mock(ObjectProvider.class);
        when(delegations.getIfAvailable()).thenReturn(registry);
        SecurityZeroTrustProperties shadow = new SecurityZeroTrustProperties();
        shadow.setMode(SecurityZeroTrustProperties.SecurityMode.SHADOW);
        ObjectProvider<SecurityZeroTrustProperties> zeroTrust = mock(ObjectProvider.class);
        when(zeroTrust.getIfAvailable()).thenReturn(shadow);
        IdentityOAuth2AutoConfiguration configuration = new IdentityOAuth2AutoConfiguration(
                mock(TransactionTemplate.class), new AuthContextProperties(), null, zeroTrust);

        configuration.tokenCustomizer(delegations, agents).customize(exchangeContext("alice"));
    }

    private static JwtEncodingContext exchangeContext(String person) {
        RegisteredClient client = RegisteredClient.withId("report-client")
                .clientId("report-client")
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .build();
        return JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256), JwtClaimsSet.builder().subject(person))
                .registeredClient(client)
                .principal(new UsernamePasswordAuthenticationToken(person, null, List.of()))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .build();
    }

    private static JwtEncodingContext accessTokenContext(String clientId) {
        RegisteredClient client = RegisteredClient.withId(clientId)
                .clientId(clientId)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        return JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256), JwtClaimsSet.builder().subject("alice"))
                .registeredClient(client)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    private IdentityOAuth2AutoConfiguration configuration(AuthContextProperties properties) {
        return new IdentityOAuth2AutoConfiguration(mock(TransactionTemplate.class), properties);
    }

    /** docs/agent OC-1: no delegation registry and no agent directory, so no delegation claim. */
    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> none() {
        return mock(ObjectProvider.class);
    }
}
