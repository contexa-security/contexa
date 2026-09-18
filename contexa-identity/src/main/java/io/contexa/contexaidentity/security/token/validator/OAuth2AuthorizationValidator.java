package io.contexa.contexaidentity.security.token.validator;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import java.util.Objects;

/** Validates access-token state owned by the local authorization server. */
public final class OAuth2AuthorizationValidator {
    private final OAuth2AuthorizationService authorizationService;

    public OAuth2AuthorizationValidator(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = Objects.requireNonNull(authorizationService, "authorizationService");
    }

    public void validateAccessToken(Jwt jwt) {
        OAuth2Authorization authorization = authorizationService.findByToken(
                jwt.getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null || authorization.getAccessToken() == null
                || !authorization.getAccessToken().isActive()
                || !Objects.equals(authorization.getPrincipalName(), jwt.getSubject())) {
            throw new InvalidBearerTokenException("The access-token authorization is not active");
        }
    }
}
