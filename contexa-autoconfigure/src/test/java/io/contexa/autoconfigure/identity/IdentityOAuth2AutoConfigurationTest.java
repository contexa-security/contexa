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
import java.util.List;

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

    private IdentityOAuth2AutoConfiguration configuration(AuthContextProperties properties) {
        return new IdentityOAuth2AutoConfiguration(mock(TransactionTemplate.class), properties);
    }
}
