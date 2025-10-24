package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.bootstrap.configurer.SecurityConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

/**
 * 플랫폼에서 사용될 SecurityConfigurer 인스턴스들을 제공하는 인터페이스입니다.
 * SecurityConfigurerOrchestrator에 의해 사용됩니다.
 */
public interface SecurityConfigurerProvider {

    /**
     * 전역 초기화 단계에서 사용될 SecurityConfigurer 리스트를 반환합니다.
     * 이 시점에서는 특정 HttpSecurity 인스턴스와 무관한 Configurer들이 주로 포함됩니다.
     * @param platformContext 플랫폼 전역 컨텍스트
     * @param platformConfig 플랫폼 전역 설정
     * @return SecurityConfigurer 리스트
     */
    List<SecurityConfigurer> getGlobalConfigurers(PlatformContext platformContext, PlatformConfig platformConfig);

    /**
     * 특정 HttpSecurity 인스턴스(즉, 특정 Flow)에 적용될 SecurityConfigurer 리스트를 반환합니다.
     * 이 메소드는 각 FlowContext 처리 시 호출될 수 있습니다.
     * @param platformContext 플랫폼 전역 컨텍스트
     * @param platformConfig 플랫폼 전역 설정
     * @param httpForScope 현재 처리 중인 HttpSecurity 인스턴스 (null이 아니어야 함).
     * 이 인스턴스의 sharedObjects를 확인하여 DSL별 커스텀 ASEP 설정을 로드한
     * AsepConfigurer 등을 포함시킬 수 있습니다.
     * @return 해당 HttpSecurity 스코프에 적용될 SecurityConfigurer 리스트
     */
    List<SecurityConfigurer>getFlowSpecificConfigurers(
            PlatformContext platformContext,
            PlatformConfig platformConfig,
            HttpSecurity httpForScope
    );
}