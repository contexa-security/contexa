package io.contexa.contexacommon.properties;

import lombok.Data;

@Data
public class JwtsTokenSettings {

    private String loginUri = "/api/login";
    private String logoutUri = "/api/logout";
    private String refreshUri = "/api/refresh";
}
