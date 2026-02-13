package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.asep.dsl.RestAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;

public interface RestConfigurerConfigurer extends AuthenticationFactorConfigurer<RestOptions, RestAsepAttributes, RestConfigurerConfigurer> {

    RestConfigurerConfigurer defaultSuccessUrl(String defaultSuccessUrl);
    RestConfigurerConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse);
    RestConfigurerConfigurer failureUrl(String failureUrl);
}

