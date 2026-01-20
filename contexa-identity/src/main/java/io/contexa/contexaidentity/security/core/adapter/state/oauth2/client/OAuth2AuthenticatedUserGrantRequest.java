package io.contexa.contexaidentity.security.core.adapter.state.oauth2.client;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;


public class OAuth2AuthenticatedUserGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

    private static final AuthorizationGrantType AUTHENTICATED_USER =
            new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user");

    private final String username;
    private final String deviceId;

    
    public OAuth2AuthenticatedUserGrantRequest(
            ClientRegistration clientRegistration,
            String username,
            @Nullable String deviceId) {

        super(AUTHENTICATED_USER, clientRegistration);
        Assert.hasText(username, "username cannot be empty");
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
