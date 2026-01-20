package io.contexa.contexacommon.properties;

import lombok.Data;


@Data
public class OttUrls {
    

    
    private String requestCodeUi = "/mfa/ott/request-code-ui";

    
    private String codeGeneration = "/mfa/ott/generate-code";

    
    private String codeSent = "/mfa/ott/code-sent";

    
    private String challengeUi = "/mfa/challenge/ott";

    
    private String loginProcessing = "/login/mfa-ott";

    
    private String defaultFailure = "/mfa/challenge/ott?error=true";

    

    
    private String singleOttRequestEmail = "/loginOtt";

    
    private String singleOttCodeGeneration = "/login/ott/generate";

    
    private String singleOttChallenge = "/loginOttVerifyCode";

    
    private String singleOttSent = "/ott/sent";
}
