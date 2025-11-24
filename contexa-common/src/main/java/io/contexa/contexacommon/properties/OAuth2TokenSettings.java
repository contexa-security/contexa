package io.contexa.contexacommon.properties;

import lombok.Data;

@Data
public class OAuth2TokenSettings {

    private String clientId = "default-client";
    private String clientSecret = "default-secret";
    private String issuerUri = "http://localhost:9000";
    private String tokenEndpoint = "/oauth2/token";
    private String scope = "read";
}
