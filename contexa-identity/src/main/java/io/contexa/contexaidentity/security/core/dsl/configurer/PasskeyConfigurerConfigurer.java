package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.asep.dsl.PasskeyAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;

import java.util.List;
import java.util.Set;

public interface PasskeyConfigurerConfigurer extends AuthenticationFactorConfigurer<PasskeyOptions, PasskeyAsepAttributes, PasskeyConfigurerConfigurer> {

    PasskeyConfigurerConfigurer assertionOptionsEndpoint(String url);
    PasskeyConfigurerConfigurer rpName(String rpName);
    PasskeyConfigurerConfigurer rpId(String rpId);
    PasskeyConfigurerConfigurer allowedOrigins(List<String> origins);
    PasskeyConfigurerConfigurer allowedOrigins(String... origins);
    PasskeyConfigurerConfigurer allowedOrigins(Set<String> origins);
}

