package io.contexa.contexacommon.properties;

import lombok.Data;


@Data
public class PasskeyUrls {
    

    
    private String loginProcessing = "/login/mfa-webauthn";

    
    private String challengeUi = "/mfa/challenge/passkey";

    
    private String defaultFailure = "/mfa/challenge/passkey?error";

    

    
    private String registrationRequest = "/mfa/passkey/register-request";

    
    private String registrationProcessing = "/mfa/passkey/register";

    

    
    private String assertionOptions = "/webauthn/authenticate/options";

    
    private String registrationOptions = "/webauthn/registration/options";
}
