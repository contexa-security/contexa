package io.contexa.contexaidentity.security.core.dsl.common;

import io.contexa.contexaidentity.security.core.dsl.option.AbstractOptions;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.List;
import java.util.Objects;

@Slf4j
public abstract class AbstractOptionsBuilderConfigurer<
        T extends AbstractOptionsBuilderConfigurer<T, O, OB, C>,
        O extends AbstractOptions,
        OB extends AbstractOptions.Builder<O, OB>,
        C extends OptionsBuilderDsl<O, C> & SecurityConfigurerDsl>
        implements OptionsBuilderDsl<O, C> {

    protected final OB optionsBuilder;
    @Setter
    private ApplicationContext applicationContext;

    protected AbstractOptionsBuilderConfigurer(OB optionsBuilder) {
        this.optionsBuilder = Objects.requireNonNull(optionsBuilder, "optionsBuilder cannot be null");
    }

    protected final ApplicationContext getApplicationContext() {
        if (this.applicationContext == null) {
            log.warn("ApplicationContext not set for {}. Some features requiring ApplicationContext may not work.", this.getClass().getSimpleName());
        }
        return this.applicationContext;
    }

    protected OB getOptionsBuilder() {
        return this.optionsBuilder;
    }

    protected abstract T self();

    @Override
    public O buildConcreteOptions() {
        return this.optionsBuilder.build();
    }

    @Override
    public C loginProcessingUrl(String url) {
        if (optionsBuilder instanceof AuthenticationProcessingOptions.AbstractAuthenticationProcessingOptionsBuilder) {
            ((AuthenticationProcessingOptions.AbstractAuthenticationProcessingOptionsBuilder<?,?>) optionsBuilder).loginProcessingUrl(url);
        } else {
            logUnsupportedOption("loginProcessingUrl");
        }
        return (C) self();
    }

    @Override
    public C successHandler(PlatformAuthenticationSuccessHandler handler) {
        if (optionsBuilder instanceof AuthenticationProcessingOptions.AbstractAuthenticationProcessingOptionsBuilder) {
            ((AuthenticationProcessingOptions.AbstractAuthenticationProcessingOptionsBuilder<?,?>) optionsBuilder).successHandler(handler);
        } else {
            logUnsupportedOption("successHandler");
        }
        return (C) self();
    }

    @Override
    public C failureHandler(PlatformAuthenticationFailureHandler handler) {
        if (optionsBuilder instanceof AuthenticationProcessingOptions.AbstractAuthenticationProcessingOptionsBuilder) {
            ((AuthenticationProcessingOptions.AbstractAuthenticationProcessingOptionsBuilder<?,?>) optionsBuilder).failureHandler(handler);
        } else {
            logUnsupportedOption("failureHandler");
        }
        return (C) self();
    }

    @Override
    public C securityContextRepository(SecurityContextRepository repository) {
        if (optionsBuilder instanceof AuthenticationProcessingOptions.AbstractAuthenticationProcessingOptionsBuilder) {
            ((AuthenticationProcessingOptions.AbstractAuthenticationProcessingOptionsBuilder<?,?>) optionsBuilder).securityContextRepository(repository);
        } else {
            logUnsupportedOption("securityContextRepository");
        }
        return (C) self();
    }

    @Override
    public C disableCsrf() {
        getOptionsBuilder().csrfDisabled(true);
        return (C) self();
    }

    @Override
    public C cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().cors(customizer);
        return (C) self();
    }

    @Override
    public C headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().headers(customizer);
        return (C) self();
    }

    @Override
    public C sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().sessionManagement(customizer);
        return (C) self();
    }

    @Override
    public C logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().logout(customizer);
        return (C) self();
    }

    @Override
    public C rawHttp(SafeHttpCustomizer<HttpSecurity> customizer) {
        getOptionsBuilder().rawHttp(customizer);
        return (C) self();
    }

    @Override
    public C authorizeStaticPermitAll(List<String> patterns) {
        getOptionsBuilder().authorizeStaticPermitAll(patterns);
        return (C) self();
    }

    @Override
    public C authorizeStaticPermitAll(String... patterns) {
        getOptionsBuilder().authorizeStaticPermitAll(patterns);
        return (C) self();
    }

    private void logUnsupportedOption(String optionName) {
        log.warn("Option '{}' is not applicable for the current OptionsBuilder type: {}. This setting will be ignored.",
                optionName, optionsBuilder.getClass().getName());
    }
}