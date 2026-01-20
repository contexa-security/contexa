package io.contexa.contexaidentity.security.core.config.oauth2;


public record ResourceServerConfig(
        String jwkSetUri,
        String issuerUri,
        OAuth2TokenType tokenType,
        String introspectionUri,
        String introspectionClientId,
        String introspectionClientSecret
) {
    
    public ResourceServerConfig() {
        this(null, null, OAuth2TokenType.JWT, null, null, null);
    }

    
    public static ResourceServerConfig jwt(String jwkSetUri, String issuerUri) {
        return new ResourceServerConfig(jwkSetUri, issuerUri, OAuth2TokenType.JWT, null, null, null);
    }

    
    public static ResourceServerConfig opaque(String introspectionUri, String clientId, String clientSecret) {
        return new ResourceServerConfig(null, null, OAuth2TokenType.OPAQUE, introspectionUri, clientId, clientSecret);
    }

    
    public enum OAuth2TokenType {
        
        JWT,

        
        OPAQUE
    }
}
