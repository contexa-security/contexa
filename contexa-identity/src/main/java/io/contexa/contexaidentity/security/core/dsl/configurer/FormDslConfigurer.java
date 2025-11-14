package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.asep.dsl.FormAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;

public interface FormDslConfigurer
        extends AuthenticationFactorConfigurer<FormOptions, FormAsepAttributes, FormDslConfigurer> { // S를 FormDslConfigurer로 명시

    FormDslConfigurer loginPage(String loginPageUrl);
    FormDslConfigurer usernameParameter(String usernameParameter);
    FormDslConfigurer passwordParameter(String passwordParameter);
    FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl);
    FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse);
    FormDslConfigurer failureUrl(String failureUrl);
    FormDslConfigurer permitAll();
    FormDslConfigurer rawFormLogin(SafeHttpFormLoginCustomizer customizer);
}