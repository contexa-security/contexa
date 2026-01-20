package io.contexa.contexacommon.properties;

import lombok.Data;


@Data
public class SinglePasskeyUrls {
    
    private String loginPage = "/login/webauthn";

    
    private String loginProcessing = "/login/webauthn";

    
    private String loginFailure = "/login/webauthn?error";

    
    private String assertionOptions = "/webauthn/authenticate/options";

    
    private String registrationOptions = "/webauthn/register/options";

    
    private String registrationRequest = "/passkey/register-request";

    
    private String registrationProcessing = "/webauthn/register";
}
