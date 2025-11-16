package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.core.asep.dsl.PasskeyAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.configurer.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.PasskeyDslConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;

import java.util.List;
import java.util.Set;

@Slf4j
public final class PasskeyDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<PasskeyDslConfigurerImpl, PasskeyOptions, PasskeyOptions.Builder, PasskeyDslConfigurer>
        implements PasskeyDslConfigurer {

    public PasskeyDslConfigurerImpl(ApplicationContext applicationContext) {
        super(PasskeyOptions.builder(applicationContext));
        setApplicationContext(applicationContext);
    }

    public PasskeyDslConfigurerImpl(ApplicationContext applicationContext, boolean isMfaMode) {
        super(isMfaMode ?
            PasskeyOptions.builderForMfa(applicationContext) :
            PasskeyOptions.builder(applicationContext)
        );
        setApplicationContext(applicationContext);
    }

    @Override
    public PasskeyDslConfigurer order(int order) {
        getOptionsBuilder().order(order); // AuthenticationProcessingOptions.Builder의 order 사용
        return self();
    }

    @Override
    public PasskeyDslConfigurer loginProcessingUrl(String url) {
        super.loginProcessingUrl(url); // AbstractOptionsBuilderConfigurer의 메서드 호출
        return self();
    }

    // --- PasskeyDslConfigurer specific methods ---
    @Override
    public PasskeyDslConfigurer assertionOptionsEndpoint(String url) {
        getOptionsBuilder().assertionOptionsEndpoint(url);
        return self();
    }

    @Override
    public PasskeyDslConfigurer rpName(String rpName) {
        getOptionsBuilder().rpName(rpName);
        return self();
    }

    @Override
    public PasskeyDslConfigurer rpId(String rpId) {
        getOptionsBuilder().rpId(rpId);
        return self();
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(List<String> origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(String... origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(Set<String> origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyDslConfigurer asep(Customizer<PasskeyAsepAttributes> passkeyAsepAttributesCustomizer){

        PasskeyAsepAttributes attributes = new PasskeyAsepAttributes();
        if (passkeyAsepAttributesCustomizer != null) {
            passkeyAsepAttributesCustomizer.customize(attributes);
        }
        getOptionsBuilder().asepAttributes(attributes);
        log.debug("ASEP: PasskeyAsepAttributes configured and will be stored within PasskeyOptions.");
        return self();
    }

    @Override
    protected PasskeyDslConfigurerImpl self() {
        return this;
    }
}
