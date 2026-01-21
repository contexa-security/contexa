package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import org.springframework.security.config.Customizer;

public interface PrimaryAuthDslConfigurer {
    PrimaryAuthDslConfigurer formLogin(Customizer<FormConfigurerConfigurer> formLoginCustomizer);
    PrimaryAuthDslConfigurer restLogin(Customizer<RestConfigurerConfigurer> restLoginCustomizer);
    PrimaryAuthenticationOptions buildOptions();
}
