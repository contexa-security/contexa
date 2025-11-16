package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import org.springframework.security.config.Customizer;

/**
 * MFA 플로우의 1차 인증(ID/PW) 설정을 위한 DSL 인터페이스.
 */
public interface PrimaryAuthDslConfigurer {
    PrimaryAuthDslConfigurer formLogin(Customizer<FormConfigurerConfigurer> formLoginCustomizer);
    PrimaryAuthDslConfigurer restLogin(Customizer<RestConfigurerConfigurer> restLoginCustomizer);
    PrimaryAuthenticationOptions buildOptions();
}
