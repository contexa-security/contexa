package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;

import java.util.List;

/**
 * 플랫폼(SecurityPlatform) 인터페이스:
 * DSL로 수집된 PlatformConfig와 AuthenticationFeature 리스트를 사용하여
 * SecurityFilterChain을 생성 및 초기화합니다.
 */
public interface SecurityPlatform {

    /**
     * DSL로 수집된 PlatformConfig와 AuthenticationFeature 리스트를 설정합니다.
     *
     * @param config   DSL 빌드 결과 PlatformConfig
     * @param features 등록된 AuthenticationFeature 구현체 리스트
     */
    void prepareGlobal(PlatformConfig config, List<?> features);

    /**
     * 등록된 모든 AuthenticationFeature를 사용하여
     * HttpSecurity 기반의 SecurityFilterChain을 구성하고 등록합니다.
     *
     * @throws Exception 구성 중 오류 발생 시
     */
    void initialize() throws Exception;
}