package io.contexa.contexaidentity.security.core.dsl.common;

import io.contexa.contexaidentity.security.core.dsl.option.AbstractOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.List;

// O: Options 타입, S: DSL Configurer 자신의 타입
public interface OptionsBuilderDsl<O extends AbstractOptions, S extends OptionsBuilderDsl<O, S>> { // O extends AbstractOptions로 변경

    // AuthenticationProcessingOptions에 특화된 메서드들
    S loginProcessingUrl(String url);
    S successHandler(PlatformAuthenticationSuccessHandler successHandler);
    S failureHandler(PlatformAuthenticationFailureHandler failureHandler);
    S securityContextRepository(SecurityContextRepository repository);

    // AbstractOptions (공통 HttpSecurity 설정) 관련 메서드들
    S disableCsrf();
    S cors(Customizer<CorsConfigurer<HttpSecurity>> customizer);
    S headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer);
    S sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer);
    S logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer);
    S rawHttp(SafeHttpCustomizer<HttpSecurity> customizer);
    S authorizeStaticPermitAll(List<String> patterns); // 추가
    S authorizeStaticPermitAll(String... patterns); // 추가

    O buildConcreteOptions();
}

