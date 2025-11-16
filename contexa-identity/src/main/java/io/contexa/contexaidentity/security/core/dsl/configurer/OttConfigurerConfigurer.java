package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.asep.dsl.OttAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

public interface OttConfigurerConfigurer extends AuthenticationFactorConfigurer<OttOptions, OttAsepAttributes, OttConfigurerConfigurer> {

    OttConfigurerConfigurer defaultSubmitPageUrl(String url);
    OttConfigurerConfigurer tokenGeneratingUrl(String url);
    OttConfigurerConfigurer showDefaultSubmitPage(boolean show);
    OttConfigurerConfigurer tokenService(OneTimeTokenService service);
    OttConfigurerConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler);
}

