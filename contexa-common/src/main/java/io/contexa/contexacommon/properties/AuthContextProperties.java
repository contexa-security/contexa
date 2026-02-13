package io.contexa.contexacommon.properties;

import io.contexa.contexacommon.enums.*;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "spring.auth")
public class AuthContextProperties {

    private StateType stateType = StateType.OAUTH2;

    private TokenTransportType tokenTransportType = TokenTransportType.HEADER;

    private TokenIssuer tokenIssuer = TokenIssuer.INTERNAL;

    private TokenStoreType tokenStoreType = TokenStoreType.REDIS;

    private FactorSelectionType factorSelectionType = FactorSelectionType.SELECT;

    @NestedConfigurationProperty
    private AuthUrlConfig urls = new AuthUrlConfig();

    @NestedConfigurationProperty
    private MfaSettings mfa = new MfaSettings(); 

    @NestedConfigurationProperty
    private JwtsTokenSettings internal = new JwtsTokenSettings();

    @NestedConfigurationProperty
    private OAuth2TokenSettings oauth2 = new OAuth2TokenSettings();

    private long accessTokenValidity = 3600000;       
    private long refreshTokenValidity = 604800000;    
    private long refreshRotateThreshold = 43200000; 

    private boolean enableRefreshToken = true;
    private boolean allowMultipleLogins = false;
    private int maxConcurrentLogins = 3;
    private boolean cookieSecure = false;

    private String tokenPrefix = "Bearer ";
    private String rolesClaim = "roles";
    private String scopesClaim = "scopes";
    private boolean oauth2Csrf = false;

}
