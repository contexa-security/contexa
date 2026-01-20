package io.contexa.contexacommon.properties;

import lombok.Data;
import org.springframework.boot.context.properties.NestedConfigurationProperty;


@Data
public class SingleAuthUrls {
    
    private String formLoginProcessing = "/login";

    
    private String formLoginPage = "/login";

    
    private String restLoginProcessing = "/api/auth/login";

    
    private String loginFailure = "/login?error";

    
    private String loginSuccess = "/";

    
    private String logoutPage = "/logout";

    
    @NestedConfigurationProperty
    private SingleOttUrls ott = new SingleOttUrls();

    
    @NestedConfigurationProperty
    private SinglePasskeyUrls passkey = new SinglePasskeyUrls();
}
