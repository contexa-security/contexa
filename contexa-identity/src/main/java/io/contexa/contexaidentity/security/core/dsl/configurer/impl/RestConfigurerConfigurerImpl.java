package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.core.asep.dsl.RestAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.configurer.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.RestConfigurerConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.context.SecurityContextRepository;

@Slf4j
public final class RestConfigurerConfigurerImpl 
        extends AbstractOptionsBuilderConfigurer<RestConfigurerConfigurerImpl, RestOptions, RestOptions.Builder, RestConfigurerConfigurer>
        implements RestConfigurerConfigurer {

    public RestConfigurerConfigurerImpl(ApplicationContext applicationContext) {
        super(RestOptions.builder(applicationContext));
        setApplicationContext(applicationContext);
    }

    public RestConfigurerConfigurerImpl(ApplicationContext applicationContext, boolean isMfaMode) {
        super(isMfaMode ? RestOptions.builderForMfa(applicationContext) : RestOptions.builder(applicationContext));
        setApplicationContext(applicationContext);
    }

    @Override
    public RestConfigurerConfigurer order(int order) {
        getOptionsBuilder().order(order); 
        return self();
    }

    @Override
    public RestConfigurerConfigurer loginProcessingUrl(String url) {
        super.loginProcessingUrl(url); 
        return self();
    }

    @Override
    public RestConfigurerConfigurer successHandler(PlatformAuthenticationSuccessHandler  successHandler) {
        super.successHandler(successHandler);
        return self();
    }

    @Override
    public RestConfigurerConfigurer failureHandler(PlatformAuthenticationFailureHandler failureHandler) {
        super.failureHandler(failureHandler);
        return self();
    }

    @Override
    public RestConfigurerConfigurer securityContextRepository(SecurityContextRepository repository) {
        super.securityContextRepository(repository);
        return self();
    }

    @Override
    public RestConfigurerConfigurer asep(Customizer<RestAsepAttributes> restAsepAttributesCustomizer){
        
        RestAsepAttributes attributes = new RestAsepAttributes();
        if (restAsepAttributesCustomizer != null) {
            restAsepAttributesCustomizer.customize(attributes);
        }
        
        getOptionsBuilder().asepAttributes(attributes); 
                return self();
    }

    @Override
    protected RestConfigurerConfigurerImpl self() {
        return this;
    }

}

