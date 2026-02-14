package io.contexa.contexacommon.properties;

import lombok.Data;

@Data
public class OAuth2TokenSettings {

    private String clientId = "default-client";
    private String clientSecret;
    private String issuerUri;
    private String tokenEndpoint = "/oauth2/token";
    private String scope = "read";
    private String redirectUri;
    private String authorizedUri;

    private String jwkKeyStorePath;
    private String jwkKeyStorePassword;
    private String jwkKeyAlias;
    private String jwkKeyPassword;
}
