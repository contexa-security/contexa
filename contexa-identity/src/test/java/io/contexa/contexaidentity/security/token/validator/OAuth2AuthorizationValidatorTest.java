package io.contexa.contexaidentity.security.token.validator;

import io.contexa.contexacommon.enums.OAuth2ServerMode;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2JwtAuthenticationConverter;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import java.time.Instant;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class OAuth2AuthorizationValidatorTest {
    final OAuth2AuthorizationService authorizations = mock(OAuth2AuthorizationService.class);
    final OAuth2AuthorizationValidator validator = new OAuth2AuthorizationValidator(authorizations);
    final Jwt jwt = Jwt.withTokenValue("owned-token").header("alg", "RS256").subject("owner").build();

    @Test void activeOwnedAuthorizationIsAccepted() {
        givenAuthorization("owner", false, false);
        assertThatCode(() -> validator.validateAccessToken(jwt)).doesNotThrowAnyException();
    }
    @Test void absentAuthorizationIsRejected() {
        assertThatThrownBy(() -> validator.validateAccessToken(jwt)).isInstanceOf(InvalidBearerTokenException.class);
    }
    @Test void invalidatedAuthorizationIsRejected() {
        givenAuthorization("owner", true, false);
        assertThatThrownBy(() -> validator.validateAccessToken(jwt)).isInstanceOf(InvalidBearerTokenException.class);
    }
    @Test void expiredAuthorizationIsRejected() {
        givenAuthorization("owner", false, true);
        assertThatThrownBy(() -> validator.validateAccessToken(jwt)).isInstanceOf(InvalidBearerTokenException.class);
    }
    @Test void differentPrincipalCannotUseAuthorization() {
        givenAuthorization("other-owner", false, false);
        assertThatThrownBy(() -> validator.validateAccessToken(jwt)).isInstanceOf(InvalidBearerTokenException.class);
    }
    @Test void resourceServerOnlyDoesNotRequireLocalAuthorizationRows() {
        try (GenericApplicationContext context = context(OAuth2ServerMode.RESOURCE_SERVER)) {
            assertThat(converter(context).convert(jwt).getName()).isEqualTo("owner");
            verifyNoInteractions(authorizations);
        }
    }
    @Test void combinedModeChecksDbBeforeLoadingUser() {
        try (GenericApplicationContext context = context(OAuth2ServerMode.COMBINED)) {
            assertThatThrownBy(() -> converter(context).convert(jwt)).isInstanceOf(InvalidBearerTokenException.class);
            givenAuthorization("owner", false, false);
            assertThat(converter(context).convert(jwt).getName()).isEqualTo("owner");
        }
    }
    GenericApplicationContext context(OAuth2ServerMode mode) {
        GenericApplicationContext context = new GenericApplicationContext();
        AuthContextProperties properties = new AuthContextProperties(); properties.setOauth2ServerMode(mode);
        context.registerBean(AuthContextProperties.class, () -> properties);
        context.registerBean(OAuth2AuthorizationService.class, () -> authorizations);
        context.registerBean(UserDetailsService.class, () -> name -> User.withUsername(name).password("unused").roles("USER").build());
        context.refresh(); return context;
    }
    OAuth2JwtAuthenticationConverter converter(GenericApplicationContext context) {
        HttpSecurity http = mock(HttpSecurity.class);
        when(http.getSharedObject(ApplicationContext.class)).thenReturn(context);
        return new OAuth2JwtAuthenticationConverter(http);
    }
    void givenAuthorization(String principal, boolean invalidated, boolean expired) {
        RegisteredClient client = RegisteredClient.withId("owned-client").clientId("owned-client")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).build();
        Instant now = Instant.now();
        OAuth2AccessToken access = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(),
                now.minusSeconds(120), expired ? now.minusSeconds(1) : now.plusSeconds(120));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client).principalName(principal)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .token(access, metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, invalidated)).build();
        when(authorizations.findByToken(jwt.getTokenValue(), OAuth2TokenType.ACCESS_TOKEN)).thenReturn(authorization);
    }
}
