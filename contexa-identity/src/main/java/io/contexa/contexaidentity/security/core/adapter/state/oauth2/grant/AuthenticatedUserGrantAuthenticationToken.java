package io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

public class AuthenticatedUserGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    public static final AuthorizationGrantType AUTHENTICATED_USER =
            new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user");

    private final String username;
    private final String deviceId;

    public AuthenticatedUserGrantAuthenticationToken(
            Authentication clientPrincipal,
            String username,
            @Nullable String deviceId,
            @Nullable Map<String, Object> additionalParameters) {

        super(AUTHENTICATED_USER, clientPrincipal, additionalParameters);
        this.username = username;
        this.deviceId = deviceId;
    }

    public String getUsername() {
        return this.username;
    }

    @Nullable
    public String getDeviceId() {
        return this.deviceId;
    }
}
