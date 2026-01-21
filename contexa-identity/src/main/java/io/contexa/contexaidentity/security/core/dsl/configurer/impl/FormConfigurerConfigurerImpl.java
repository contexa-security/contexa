package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.core.asep.dsl.FormAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.configurer.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.contexa.contexaidentity.security.core.dsl.configurer.FormConfigurerConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.context.SecurityContextRepository;

@Slf4j
public final class FormConfigurerConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<FormConfigurerConfigurerImpl, FormOptions, FormOptions.Builder, FormConfigurerConfigurer>
        implements FormConfigurerConfigurer {

    public FormConfigurerConfigurerImpl(ApplicationContext applicationContext) {
        super(FormOptions.builder(applicationContext));
        setApplicationContext(applicationContext);
    }

    public FormConfigurerConfigurerImpl(ApplicationContext applicationContext, boolean isMfaMode) {
        super(isMfaMode ? FormOptions.builderForMfa(applicationContext) : FormOptions.builder(applicationContext));
        setApplicationContext(applicationContext);
    }

    @Override
    public FormConfigurerConfigurer order(int order) {
        getOptionsBuilder().order(order);
        return self();
    }

    @Override
    public FormConfigurerConfigurer loginPage(String loginPageUrl) {
        getOptionsBuilder().loginPage(loginPageUrl);
        return self();
    }

    @Override
    public FormConfigurerConfigurer loginProcessingUrl(String loginProcessingUrl) {
        getOptionsBuilder().loginProcessingUrl(loginProcessingUrl);
        return self();
    }

    @Override
    public FormConfigurerConfigurer usernameParameter(String usernameParameter) {
        getOptionsBuilder().usernameParameter(usernameParameter);
        return self();
    }

    @Override
    public FormConfigurerConfigurer passwordParameter(String passwordParameter) {
        getOptionsBuilder().passwordParameter(passwordParameter);
        return self();
    }

    @Override
    public FormConfigurerConfigurer defaultSuccessUrl(String defaultSuccessUrl) {
        getOptionsBuilder().defaultSuccessUrl(defaultSuccessUrl);
        return self();
    }

    @Override
    public FormConfigurerConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        getOptionsBuilder().defaultSuccessUrl(defaultSuccessUrl, alwaysUse);
        return self();
    }

    @Override
    public FormConfigurerConfigurer failureUrl(String failureUrl) {
        getOptionsBuilder().failureUrl(failureUrl);
        return self();
    }

    @Override
    public FormConfigurerConfigurer permitAll() {
        getOptionsBuilder().permitAll();
        return self();
    }

    @Override
    public FormConfigurerConfigurer successHandler(PlatformAuthenticationSuccessHandler successHandler) {
        getOptionsBuilder().successHandler(successHandler);
        return self();
    }

    @Override
    public FormConfigurerConfigurer failureHandler(PlatformAuthenticationFailureHandler failureHandler) {
        getOptionsBuilder().failureHandler(failureHandler);
        return self();
    }

    @Override
    public FormConfigurerConfigurer securityContextRepository(SecurityContextRepository repository) {
        getOptionsBuilder().securityContextRepository(repository);
        return self();
    }

    @Override
    public FormConfigurerConfigurer rawFormLogin(SafeHttpFormLoginCustomizer customizer) {
        getOptionsBuilder().rawFormLoginCustomizer(customizer);
        return self();
    }

    @Override
    public FormConfigurerConfigurer asep(Customizer<FormAsepAttributes> formAsepAttributesCustomizer) {
        FormAsepAttributes attributes = new FormAsepAttributes();
        if (formAsepAttributesCustomizer != null) {
            formAsepAttributesCustomizer.customize(attributes);
        }
        
        getOptionsBuilder().asepAttributes(attributes);
                return self();
    }

    @Override
    protected FormConfigurerConfigurerImpl self() {
        return this;
    }
}