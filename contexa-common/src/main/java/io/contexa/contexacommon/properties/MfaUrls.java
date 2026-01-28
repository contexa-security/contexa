package io.contexa.contexacommon.properties;

import lombok.Data;


@Data
public class MfaUrls {

    private String selectFactor = "/mfa/select-factor";

    private String success = "/main";

    private String failure = "/mfa/failure";

    private String cancel = "/mfa/cancel";

    private String status = "/mfa/status";

    private String requestOttCode = "/mfa/request-ott-code";

    private String config = "/api/mfa/config";
}
