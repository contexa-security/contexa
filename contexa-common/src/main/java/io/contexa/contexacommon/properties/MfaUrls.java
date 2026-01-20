package io.contexa.contexacommon.properties;

import lombok.Data;


@Data
public class MfaUrls {
    
    private String initiate = "/mfa/initiate";

    
    private String configure = "/mfa/configure";

    
    private String selectFactor = "/mfa/select-factor";

    
    private String success = "/home";

    
    private String failure = "/mfa/failure";

    
    private String cancel = "/mfa/cancel";

    
    private String cancelRedirect = "/loginForm";

    
    private String status = "/mfa/status";

    
    private String context = "/api/mfa/context";

    
    private String requestOttCode = "/mfa/request-ott-code";

    
    private String config = "/api/mfa/config";
}
