package io.contexa.contexacommon.properties;

import lombok.Data;


@Data
public class PrimaryAuthUrls {
    
    private String formLoginProcessing = "/mfa/login";

    
    private String formLoginPage = "/mfa/login";

    
    private String restLoginProcessing = "/api/mfa/login";

    
    private String loginFailure = "/login?error";

    
    private String loginSuccess = "/";

    
    private String logoutPage = "/logout";
}
