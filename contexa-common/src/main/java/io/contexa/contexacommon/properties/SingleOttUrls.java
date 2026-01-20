package io.contexa.contexacommon.properties;

import lombok.Data;


@Data
public class SingleOttUrls {
    
    private String requestEmail = "/login/ott";

    
    private String codeGeneration = "/ott/generate";

    
    private String codeSent = "/login/ott/sent";

    
    private String challenge = "/login/ott/verify";

    
    private String loginProcessing = "/login/ott";

    
    private String loginFailure = "/login/ott?error";
}
