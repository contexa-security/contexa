package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.core.dsl.configurer.FormDslConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.PrimaryAuthDslConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.RestDslConfigurer;
import io.contexa.contexaidentity.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.util.Assert;

import java.util.Objects;

@Slf4j
@Getter
public final class PrimaryAuthDslConfigurerImpl<H extends HttpSecurityBuilder<H>>
        implements PrimaryAuthDslConfigurer {

    private Customizer<FormDslConfigurer> formLoginCustomizer;
    private Customizer<RestDslConfigurer> restLoginCustomizer;
    private final ApplicationContext applicationContext;

    public PrimaryAuthDslConfigurerImpl(ApplicationContext applicationContext) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");
    }

    @Override
    public PrimaryAuthDslConfigurer formLogin(Customizer<FormDslConfigurer> formLoginCustomizer) {
        Assert.notNull(formLoginCustomizer, "formLoginCustomizer cannot be null");
        this.formLoginCustomizer = formLoginCustomizer;
        this.restLoginCustomizer = null;
        return this;
    }

    @Override
    public PrimaryAuthDslConfigurer restLogin(Customizer<RestDslConfigurer> restLoginCustomizer) {
        Assert.notNull(restLoginCustomizer, "restLoginCustomizer cannot be null");
        this.restLoginCustomizer = restLoginCustomizer;
        this.formLoginCustomizer = null;
        return this;
    }

    @Override
    public PrimaryAuthenticationOptions buildOptions() {
        PrimaryAuthenticationOptions.Builder optionsBuilder = PrimaryAuthenticationOptions.builder();
        String determinedLoginProcessingUrl = null;

        AuthMethodConfigurerFactory factory = new AuthMethodConfigurerFactory(this.applicationContext);

        if (formLoginCustomizer != null) {
            FormDslConfigurerImpl formDslBuilder = (FormDslConfigurerImpl) factory.createFactorConfigurer(
                    AuthType.FORM, FormDslConfigurer.class
            );
            formDslBuilder.setApplicationContext(this.applicationContext);
            formLoginCustomizer.customize(formDslBuilder);
            FormOptions builtFormOptions = formDslBuilder.buildConcreteOptions();

            optionsBuilder.formOptions(builtFormOptions);
            determinedLoginProcessingUrl = builtFormOptions.getLoginProcessingUrl();
            log.debug("PrimaryAuth: FormLogin options built. Processing URL: {}", determinedLoginProcessingUrl);

        } else if (restLoginCustomizer != null) {
            RestDslConfigurerImpl restDslBuilder = (RestDslConfigurerImpl) factory.createFactorConfigurer(
                    AuthType.MFA_REST, RestDslConfigurer.class
            );
            restDslBuilder.setApplicationContext(this.applicationContext);
            restLoginCustomizer.customize(restDslBuilder);
//            RestOptions builtRestOptions = restDslBuilder.buildConcreteOptions();
            RestOptions builtRestOptions = (RestOptions) restDslBuilder.buildConcreteOptions();

            optionsBuilder.restOptions(builtRestOptions);
            determinedLoginProcessingUrl = builtRestOptions.getLoginProcessingUrl();
            log.debug("PrimaryAuth: RestLogin options built. Processing URL: {}", determinedLoginProcessingUrl);
        } else {
            // 이 메서드가 호출되었다는 것은 formLoginCustomizer 또는 restLoginCustomizer 중 하나는 설정되었음을 의미해야 함.
            // MfaDslConfigurerImpl.build()에서 호출 전에 이 조건을 확인.
            throw new DslConfigurationException("Neither formLogin nor restLogin was configured for primary authentication, but buildOptions was called.");
        }

        Assert.hasText(determinedLoginProcessingUrl,
                "loginProcessingUrl could not be determined from FormLogin or RestLogin configuration.");
        optionsBuilder.loginProcessingUrl(determinedLoginProcessingUrl);

        return optionsBuilder.build();
    }
}