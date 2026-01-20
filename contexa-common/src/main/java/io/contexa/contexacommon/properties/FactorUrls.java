package io.contexa.contexacommon.properties;

import lombok.Data;
import org.springframework.boot.context.properties.NestedConfigurationProperty;


@Data
public class FactorUrls {
    @NestedConfigurationProperty
    private OttUrls ott = new OttUrls();

    @NestedConfigurationProperty
    private PasskeyUrls passkey = new PasskeyUrls();

    
    private String recoveryCodeLoginProcessing = "/login/recovery/verify";

    
    private String recoveryCodeChallengeUi = "/mfa/challenge/recovery";
}
