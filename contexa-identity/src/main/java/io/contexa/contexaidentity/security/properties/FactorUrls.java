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

    /**
     * Recovery Code 검증 처리 URL (POST) - Filter가 처리
     */
    private String recoveryCodeLoginProcessing = "/login/recovery/verify";

    /**
     * Recovery Code 챌린지 UI 페이지
     */
    private String recoveryCodeChallengeUi = "/mfa/challenge/recovery";
}
