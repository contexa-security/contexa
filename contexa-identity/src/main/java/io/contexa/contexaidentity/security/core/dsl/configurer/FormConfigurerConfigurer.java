package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.asep.dsl.FormAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;

public interface FormConfigurerConfigurer
        extends AuthenticationFactorConfigurer<FormOptions, FormAsepAttributes, FormConfigurerConfigurer> { 

    FormConfigurerConfigurer loginPage(String loginPageUrl);
    FormConfigurerConfigurer usernameParameter(String usernameParameter);
    FormConfigurerConfigurer passwordParameter(String passwordParameter);
    FormConfigurerConfigurer defaultSuccessUrl(String defaultSuccessUrl);
    FormConfigurerConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse);
    FormConfigurerConfigurer failureUrl(String failureUrl);
    FormConfigurerConfigurer permitAll();
    FormConfigurerConfigurer rawFormLogin(SafeHttpFormLoginCustomizer customizer);
}