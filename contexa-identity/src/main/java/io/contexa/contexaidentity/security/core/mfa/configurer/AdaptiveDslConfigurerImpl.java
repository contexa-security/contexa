package io.contexa.contexaidentity.security.core.mfa.configurer;

import io.contexa.contexaidentity.security.core.mfa.AdaptiveConfig;

/**
 * Adaptive DSL 구현체: 컨텍스트 기반 조건부 MFA 설정
 */
public class AdaptiveDslConfigurerImpl implements AdaptiveDslConfigurer {
    private boolean geolocation = false;
    private boolean devicePosture = false;

    @Override
    public AdaptiveDslConfigurer geolocation(boolean enable) {
        this.geolocation = enable;
        return this;
    }

    @Override
    public AdaptiveDslConfigurer devicePosture(boolean enable) {
        this.devicePosture = enable;
        return this;
    }

    @Override
    public AdaptiveConfig build() {
        return new AdaptiveConfig(geolocation, devicePosture);
    }
}
