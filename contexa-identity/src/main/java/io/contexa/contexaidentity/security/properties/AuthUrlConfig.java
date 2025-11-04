package io.contexa.contexaidentity.security.properties;

import lombok.Data;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * 중앙 집중식 인증 URL 설정
 * <p>
 * 모든 인증 관련 URL을 한 곳에서 관리하는 단일 진실의 원천(Single Source of Truth).
 * 필터, Configurer, 컨트롤러, SDK 모두 이 설정을 통해 URL에 접근해야 함.
 * <p>
 * 설정 경로: {@code spring.auth.urls}
 *
 * @since 2025-01
 */
@Data
public class AuthUrlConfig {

    @NestedConfigurationProperty
    private PrimaryAuthUrls primary = new PrimaryAuthUrls();

    @NestedConfigurationProperty
    private MfaUrls mfa = new MfaUrls();

    @NestedConfigurationProperty
    private FactorUrls factors = new FactorUrls();
}
