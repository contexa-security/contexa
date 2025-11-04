package io.contexa.contexaidentity.security.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Getter
@Setter
public class PasskeyFactorSettings {
    /**
     * Passkey 관련 URL 설정
     */
    @NestedConfigurationProperty
    private PasskeyUrls urls = new PasskeyUrls();

    /**
     * Passkey assertion/registration 타임아웃 (초)
     */
    private int timeoutSeconds = 60;

    /**
     * WebAuthn Relying Party ID (기본값: localhost)
     */
    private String rpId = "localhost";

    /**
     * WebAuthn Relying Party Name (기본값: Contexa Platform)
     */
    private String rpName = "Contexa Platform";
}
