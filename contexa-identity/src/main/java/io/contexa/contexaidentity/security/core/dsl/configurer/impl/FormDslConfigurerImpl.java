package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.core.asep.dsl.FormAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.contexa.contexaidentity.security.core.dsl.configurer.FormDslConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.context.SecurityContextRepository;

@Slf4j
public final class FormDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<FormDslConfigurerImpl, FormOptions, FormOptions.Builder, FormDslConfigurer>
        implements FormDslConfigurer {

    public FormDslConfigurerImpl(ApplicationContext applicationContext) {
        super(FormOptions.builder(applicationContext));
        setApplicationContext(applicationContext);
    }

    @Override
    public FormDslConfigurer order(int order) {
        getOptionsBuilder().order(order);
        return self();
    }

    @Override
    public FormDslConfigurer loginPage(String loginPageUrl) {
        getOptionsBuilder().loginPage(loginPageUrl);
        return self();
    }

    @Override
    public FormDslConfigurer loginProcessingUrl(String loginProcessingUrl) {
        getOptionsBuilder().loginProcessingUrl(loginProcessingUrl);
        return self();
    }

    @Override
    public FormDslConfigurer usernameParameter(String usernameParameter) {
        getOptionsBuilder().usernameParameter(usernameParameter);
        return self();
    }

    @Override
    public FormDslConfigurer passwordParameter(String passwordParameter) {
        getOptionsBuilder().passwordParameter(passwordParameter);
        return self();
    }

    @Override
    public FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        getOptionsBuilder().defaultSuccessUrl(defaultSuccessUrl, alwaysUse);
        return self();
    }

    @Override
    public FormDslConfigurer failureUrl(String failureUrl) {
        getOptionsBuilder().failureUrl(failureUrl);
        return self();
    }

    @Override
    public FormDslConfigurer permitAll() {
        getOptionsBuilder().permitAll();
        return self();
    }

    @Override
    public FormDslConfigurer successHandler(PlatformAuthenticationSuccessHandler successHandler) {
        getOptionsBuilder().successHandler(successHandler);
        return self();
    }

    @Override
    public FormDslConfigurer failureHandler(PlatformAuthenticationFailureHandler failureHandler) {
        getOptionsBuilder().failureHandler(failureHandler);
        return self();
    }

    @Override
    public FormDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        getOptionsBuilder().securityContextRepository(repository);
        return self();
    }

    @Override
    public FormDslConfigurer rawFormLogin(SafeHttpFormLoginCustomizer customizer) {
        getOptionsBuilder().rawFormLoginCustomizer(customizer);
        return self();
    }

    @Override
    public FormDslConfigurer asep(Customizer<FormAsepAttributes> formAsepAttributesCustomizer) {
        FormAsepAttributes attributes = new FormAsepAttributes();
        if (formAsepAttributesCustomizer != null) {
            formAsepAttributesCustomizer.customize(attributes);
        }
        // FormOptions.Builder에 asepAttributes를 설정하는 메서드 호출
        getOptionsBuilder().asepAttributes(attributes);
        log.debug("ASEP: FormAsepAttributes configured and will be stored within FormOptions.");
        return self();
    }

    @Override
    protected FormDslConfigurerImpl self() {
        return this;
    }
}