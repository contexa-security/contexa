package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.asep.dsl.BaseAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.common.SecurityConfigurerDsl;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import org.springframework.security.config.Customizer;

public interface AuthenticationFactorConfigurer<
        O extends AuthenticationProcessingOptions,
        A extends BaseAsepAttributes,
        S extends AuthenticationFactorConfigurer<O, A, S>>
        extends OptionsBuilderConfigurer<O, S>, SecurityConfigurerDsl {

    S order(int order);
    S asep(Customizer<A> asepAttributesCustomizer);
}
