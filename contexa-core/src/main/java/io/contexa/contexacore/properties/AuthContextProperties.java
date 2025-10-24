package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "spring.auth")
public class AuthContextProperties {
    /**
     * MFA 관련 설정
     */
    @NestedConfigurationProperty
    private MfaSettings mfa = new MfaSettings(); // 기본 인스턴스 생성

}


