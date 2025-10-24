package io.contexa.contexaidentity.security.core.mfa.configurer;

import io.contexa.contexaidentity.security.core.mfa.AdaptiveConfig;

/**
 * 컨텍스트 기반 어댑티브 정책 설정용 DSL 인터페이스
 */
public interface AdaptiveDslConfigurer  {
    AdaptiveDslConfigurer geolocation(boolean enable);
    AdaptiveDslConfigurer devicePosture(boolean enable);
    AdaptiveConfig build();
}