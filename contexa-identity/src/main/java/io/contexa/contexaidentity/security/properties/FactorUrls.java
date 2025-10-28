package io.contexa.contexaidentity.security.properties;

import lombok.Data;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Factor별 URL 설정
 */
@Data
public class FactorUrls {
    @NestedConfigurationProperty
    private OttUrls ott = new OttUrls();

    @NestedConfigurationProperty
    private PasskeyUrls passkey = new PasskeyUrls();

    @NestedConfigurationProperty
    private RecoveryCodeUrls recoveryCode = new RecoveryCodeUrls();
}
