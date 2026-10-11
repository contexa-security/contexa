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
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
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
import java.util.Date;
import java.util.List;
import java.util.Map;
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
                configuration(new AuthContextProperties()).tokenCustomizer();

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
    @DisplayName("A token the real token engine issues carries the login facts, and its stored claims read back")
    void issuedTokenClaimsReadBackFromTheStoredAuthorization() throws Exception {
        IdentityOAuth2AutoConfiguration configuration = configuration(new AuthContextProperties());
        JwtGenerator generator = new JwtGenerator(new NimbusJwtEncoder(configuration.jwkSource()));
        generator.setJwtCustomizer(configuration.tokenCustomizer());
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

    private IdentityOAuth2AutoConfiguration configuration(AuthContextProperties properties) {
        return new IdentityOAuth2AutoConfiguration(mock(TransactionTemplate.class), properties);
    }
}
