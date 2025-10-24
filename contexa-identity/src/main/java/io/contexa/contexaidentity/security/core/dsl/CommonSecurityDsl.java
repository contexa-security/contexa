package io.contexa.contexaidentity.security.core.dsl;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;

/**
 * 다양한 DSL Configurer 들이 공통적으로 제공할 수 있는 상위 레벨 HttpSecurity 설정 메소드.
 * 대부분의 구체적인 설정은 OptionsBuilderDsl로 이동하였으므로, 이 인터페이스는 필요에 따라 축소되거나
 * OptionsBuilderDsl과 통합될 수 있습니다.
 * @param <S> Self-type 으로, 이 인터페이스를 구현하는 Configurer 자신의 타입
 */
public interface CommonSecurityDsl<S extends CommonSecurityDsl<S>> {
    S disableCsrf();
    S cors(Customizer<CorsConfigurer<HttpSecurity>> customizer);
    S headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer);
    S sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer);
    S logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer);
}