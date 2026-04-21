package io.contexa.autoconfigure.identity;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdentityOAuth2AutoConfigurationTest {

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
    @DisplayName("Internal client registration should reuse stored noop secret when property is blank")
    void clientRegistrationUsesStoredNoopSecretWhenPropertyBlank() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret("");
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
    @DisplayName("Internal client registration should generate a secret when property and stored client are blank")
    void clientRegistrationGeneratesInternalSecretWhenPropertyAndStoredClientAreBlank() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret("");
        IdentityOAuth2AutoConfiguration configuration = configuration(properties);

        RegisteredClientRepository registeredClientRepository = mock(RegisteredClientRepository.class);
        when(registeredClientRepository.findByClientId(properties.getOauth2().getClientId()))
                .thenReturn(null);

        ClientRegistrationRepository repository =
                configuration.clientRegistrationRepository(registeredClientRepository);

        ClientRegistration registration = repository.findByRegistrationId("aidc-internal");
        assertThat(registration.getClientSecret()).isNotBlank();
    }

    private IdentityOAuth2AutoConfiguration configuration(AuthContextProperties properties) {
        return new IdentityOAuth2AutoConfiguration(mock(TransactionTemplate.class), properties);
    }
}
