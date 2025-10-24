package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.core.asep.dsl.OttAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.OttDslConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

@Slf4j
public final class OttDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<OttDslConfigurerImpl, OttOptions, OttOptions.Builder, OttDslConfigurer>
        implements OttDslConfigurer {

    public OttDslConfigurerImpl(ApplicationContext applicationContext) {
        super(OttOptions.builder(applicationContext));
        setApplicationContext(applicationContext);
    }

    @Override
    public OttDslConfigurer order(int order) {
        getOptionsBuilder().order(order);
        return self();
    }

    @Override
    public OttDslConfigurer loginProcessingUrl(String url) {
        getOptionsBuilder().loginProcessingUrl(url);
        return self();
    }

    @Override
    public OttDslConfigurer successHandler(PlatformAuthenticationSuccessHandler successHandler) {
        getOptionsBuilder().successHandler(successHandler);
        return self();
    }

    @Override
    public OttDslConfigurer failureHandler(PlatformAuthenticationFailureHandler failureHandler) {
        getOptionsBuilder().failureHandler(failureHandler);
        return self();
    }

    @Override
    public OttDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        getOptionsBuilder().securityContextRepository(repository);
        return self();
    }

    @Override
    public OttDslConfigurer defaultSubmitPageUrl(String url) {
        getOptionsBuilder().defaultSubmitPageUrl(url);
        return self();
    }

    @Override
    public OttDslConfigurer tokenGeneratingUrl(String url) {
        getOptionsBuilder().tokenGeneratingUrl(url);
        return self();
    }

    @Override
    public OttDslConfigurer showDefaultSubmitPage(boolean show) {
        getOptionsBuilder().showDefaultSubmitPage(show);
        return self();
    }

    @Override
    public OttDslConfigurer tokenService(OneTimeTokenService service) {
        getOptionsBuilder().oneTimeTokenService(service); // OttOptions.Builder에 해당 메소드 필요
        return self();
    }

    @Override
    public OttDslConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
        getOptionsBuilder().tokenGenerationSuccessHandler(handler); // OttOptions.Builder에 해당 메소드 필요
        return self();
    }

    @Override
    public OttDslConfigurer asep(Customizer<OttAsepAttributes> ottAsepAttributesCustomizer) {

        OttAsepAttributes attributes = new OttAsepAttributes();
        if (ottAsepAttributesCustomizer != null) {
            ottAsepAttributesCustomizer.customize(attributes);
        }
        // builder.setSharedObject(PasskeyAsepAttributes.class, attributes); // 제거
        getOptionsBuilder().asepAttributes(attributes); // PasskeyOptions.Builder에 저장
        log.debug("ASEP: PasskeyAsepAttributes configured and will be stored within PasskeyOptions.");
        return self();
    }

    @Override
    protected OttDslConfigurerImpl self() {
        return this;
    }
}

