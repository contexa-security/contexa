package io.contexa.contexacommon.properties;

import lombok.Data;

@Data
public class OAuth2TokenSettings {

    private String clientId = "default-client";
    private String clientSecret = "173f8245-5f7d-4623-a612-aa0c68f6da4a";
    private String issuerUri = "http://localhost:9000";
    private String tokenEndpoint = "/oauth2/token";
    private String scope = "read";
    private String redirectUri = "http://localhost:8080";
    private String authorizedUri;

    private String jwkKeyStorePath;
    private String jwkKeyStorePassword;
    private String jwkKeyAlias;
    private String jwkKeyPassword;
}
