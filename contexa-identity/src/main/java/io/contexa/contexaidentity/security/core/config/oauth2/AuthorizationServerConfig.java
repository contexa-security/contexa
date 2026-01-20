package io.contexa.contexaidentity.security.core.config.oauth2;


public record AuthorizationServerConfig(
        String issuerUri,
        String authorizationEndpoint,
        String tokenEndpoint,
        String jwkSetEndpoint,
        String introspectionEndpoint,
        String revocationEndpoint,
        boolean enableOidc,
        String userInfoEndpoint,
        long accessTokenValidity,
        long refreshTokenValidity
) {
    
    public AuthorizationServerConfig() {
        this(
                null,
                "/oauth2/authorize",
                "/oauth2/token",
                "/oauth2/jwks",
                "/oauth2/introspect",
                "/oauth2/revoke",
                false,
                "/oauth2/userinfo",
                3600L,
                86400L
        );
    }

    
    public static AuthorizationServerConfig defaults(String issuerUri) {
        return new AuthorizationServerConfig(
                issuerUri,
                "/oauth2/authorize",
                "/oauth2/token",
                "/oauth2/jwks",
                "/oauth2/introspect",
                "/oauth2/revoke",
                false,
                "/oauth2/userinfo",
                3600L,
                86400L
        );
    }

    
    public static AuthorizationServerConfig withOidc(String issuerUri) {
        return new AuthorizationServerConfig(
                issuerUri,
                "/oauth2/authorize",
                "/oauth2/token",
                "/oauth2/jwks",
                "/oauth2/introspect",
                "/oauth2/revoke",
                true,
                "/oauth2/userinfo",
                3600L,
                86400L
        );
    }
}
