package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.core.asep.dsl.BaseAsepAttributes;
import io.contexa.contexaidentity.security.core.asep.dsl.MfaAsepAttributes;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.configurer.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.*;
import io.contexa.contexaidentity.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import io.contexa.contexaidentity.security.exceptionhandling.MfaAuthenticationEntryPoint;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexacommon.properties.MfaPageConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.*;

@Slf4j
public final class MfaDslConfigurerImpl<H extends HttpSecurityBuilder<H>>
        implements MfaDslConfigurer {

    private final AuthenticationFlowConfig.Builder flowConfigBuilder;
    private final AuthMethodConfigurerFactory authMethodConfigurerFactory;
    private final ApplicationContext applicationContext;

    private MfaPolicyProvider policyProvider;
    private PlatformAuthenticationFailureHandler mfaFailureHandler;
    private AuthenticationSuccessHandler finalSuccessHandler;
    private boolean defaultDeviceTrustEnabled = false;
    private int order = 200;

    private final List<AuthenticationStepConfig> configuredSteps = new ArrayList<>();
    private int currentStepOrderCounter = 1;

    private final PrimaryAuthDslConfigurerImpl<H> primaryAuthConfigurer;
    private MfaAsepAttributes mfaAsepAttributes;
    private MfaPageConfig mfaPageConfig;

    private String mfaFlowTypeName = MfaFlowTypeUtils.getBaseMfaTypeName();
    private String userDefinedFlowName;
    private String urlPrefix;

    public MfaDslConfigurerImpl(ApplicationContext applicationContext) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");
        this.flowConfigBuilder = AuthenticationFlowConfig.builder(MfaFlowTypeUtils.getBaseMfaTypeName());
        this.authMethodConfigurerFactory = new AuthMethodConfigurerFactory(this.applicationContext);
        this.primaryAuthConfigurer = new PrimaryAuthDslConfigurerImpl<>(this.applicationContext);
    }

    @Override
    public MfaDslConfigurerImpl<H> name(String flowName) {
        this.userDefinedFlowName = flowName;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> urlPrefix(String urlPrefix) {
        this.urlPrefix = urlPrefix;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfigCustomizer) {
        Objects.requireNonNull(primaryAuthConfigCustomizer, "primaryAuthConfigCustomizer cannot be null");
        primaryAuthConfigCustomizer.customize(this.primaryAuthConfigurer);
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> form(Customizer<FormConfigurerConfigurer> formConfigurerCustomizer) {
        throw new UnsupportedOperationException("Use .primaryAuthentication(primary -> primary.formLogin(...)) for MFA flow's primary auth.");
    }

    @Override
    public MfaDslConfigurerImpl<H> rest(Customizer<RestConfigurerConfigurer> restConfigurerCustomizer) {
        throw new UnsupportedOperationException("Use .primaryAuthentication(primary -> primary.restLogin(...)) for MFA flow's primary auth.");
    }

    private <O_FACTOR extends AuthenticationProcessingOptions,
            A_FACTOR extends BaseAsepAttributes,
            C_FACTOR extends AuthenticationFactorConfigurer<O_FACTOR, A_FACTOR, C_FACTOR>> MfaDslConfigurerImpl<H> configureMfaFactor(
            AuthType authType,
            Customizer<C_FACTOR> factorConfigurerCustomizer,
            Class<C_FACTOR> configurerInterfaceType) {

        C_FACTOR configurer = authMethodConfigurerFactory.createFactorConfigurer(authType, configurerInterfaceType);

        if (configurer instanceof AbstractOptionsBuilderConfigurer) {
            ((AbstractOptionsBuilderConfigurer<?, O_FACTOR, ?, C_FACTOR>) configurer).setApplicationContext(this.applicationContext);
        }

        Objects.requireNonNull(factorConfigurerCustomizer, authType.name() + " customizer cannot be null").customize(configurer);
        O_FACTOR factorOptions = configurer.buildConcreteOptions();

        int stepOrder = currentStepOrderCounter++;
        AuthenticationStepConfig factorStep = new AuthenticationStepConfig(this.mfaFlowTypeName, authType.name(), stepOrder, false);
        factorStep.getOptions().put("_options", factorOptions);
        this.configuredSteps.add(factorStep);
                return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> ott(Customizer<OttConfigurerConfigurer> ottConfigurerCustomizer) {
        return configureMfaFactor(AuthType.MFA_OTT, ottConfigurerCustomizer, OttConfigurerConfigurer.class);
    }

    @Override
    public MfaDslConfigurerImpl<H> passkey(Customizer<PasskeyConfigurerConfigurer> passkeyConfigurerCustomizer) {
        return configureMfaFactor(AuthType.MFA_PASSKEY, passkeyConfigurerCustomizer, PasskeyConfigurerConfigurer.class);
    }

    @Override
    public MfaDslConfigurerImpl<H> mfaFailureHandler(PlatformAuthenticationFailureHandler  failureHandler) {
        this.mfaFailureHandler = failureHandler;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> policyProvider(MfaPolicyProvider policyProvider) {
        this.policyProvider = policyProvider;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> mfaSuccessHandler(PlatformAuthenticationSuccessHandler handler) {
        this.finalSuccessHandler = handler;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> defaultDeviceTrustEnabled(boolean enable) {
        this.defaultDeviceTrustEnabled = enable;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> asep(Customizer<MfaAsepAttributes> mfaAsepAttributesCustomizer) {
        this.mfaAsepAttributes = new MfaAsepAttributes();
        if (mfaAsepAttributesCustomizer != null) {
            mfaAsepAttributesCustomizer.customize(this.mfaAsepAttributes);
        }
                return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> mfaPage(Customizer<MfaPageConfigurer> mfaPageConfigurerCustomizer) {
        Objects.requireNonNull(mfaPageConfigurerCustomizer, "mfaPageConfigurerCustomizer cannot be null");
        MfaPageConfigurer configurer = new MfaPageConfigurer();
        mfaPageConfigurerCustomizer.customize(configurer);
        this.mfaPageConfig = configurer.getConfig();
                return this;
    }

    /**
     * Returns the user-defined flow name set via name(), or null if not set.
     * Used by AbstractFlowRegistrar for auto-numbering logic.
     */
    public String getUserDefinedFlowName() {
        return this.userDefinedFlowName;
    }

    @Override
    public AuthenticationFlowConfig build() {
        if (StringUtils.hasText(this.userDefinedFlowName)) {
            this.mfaFlowTypeName = MfaFlowTypeUtils.generateTypeName(this.userDefinedFlowName);
        }

        PrimaryAuthenticationOptions primaryAuthOptionsForFlow = null;

        if (this.primaryAuthConfigurer.getFormLoginCustomizer() != null || this.primaryAuthConfigurer.getRestLoginCustomizer() != null) {
            primaryAuthOptionsForFlow = this.primaryAuthConfigurer.buildOptions();
            AuthenticationProcessingOptions primaryConcreteOptions = primaryAuthOptionsForFlow.isFormLogin() ?
                    primaryAuthOptionsForFlow.getFormOptions() : primaryAuthOptionsForFlow.getRestOptions();
            AuthType primaryAuthType = primaryAuthOptionsForFlow.isFormLogin() ? AuthType.MFA_FORM : AuthType.MFA_REST;

            configuredSteps.removeIf(s -> s.getOrder() == 0);

            AuthenticationStepConfig primaryAuthStep = new AuthenticationStepConfig(this.mfaFlowTypeName, primaryAuthType.name(), 0, true);
            primaryAuthStep.getOptions().put("_options", primaryConcreteOptions);
            configuredSteps.addFirst(primaryAuthStep);
                    } else {

            if (configuredSteps.isEmpty() || configuredSteps.getFirst().getOrder() != 0) {
                throw new DslConfigurationException("MFA flow [" + this.mfaFlowTypeName + "] must have a primary authentication step (order 0) or use .primaryAuthentication() DSL.");
            }
            Object firstStepOptionsObj = configuredSteps.getFirst().getOptions().get("_options");
            if (firstStepOptionsObj instanceof FormOptions fo) {
                primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder().formOptions(fo).loginProcessingUrl(fo.getLoginProcessingUrl()).build();
            } else if (firstStepOptionsObj instanceof RestOptions ro) {
                primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder().restOptions(ro).loginProcessingUrl(ro.getLoginProcessingUrl()).build();
            } else {
                throw new DslConfigurationException("Could not determine PrimaryAuthenticationOptions from the first step of MFA flow ["+ this.mfaFlowTypeName +"].");
            }
        }

        Assert.isTrue(!configuredSteps.isEmpty(), "MFA flow ["+ this.mfaFlowTypeName +"] must have at least one authentication step (primary).");
        configuredSteps.sort(Comparator.comparingInt(AuthenticationStepConfig::getOrder));

        AuthenticationStepConfig firstConfiguredStep = configuredSteps.getFirst();
        Assert.isTrue(firstConfiguredStep.getOrder() == 0, "MFA flow's first step must have order 0.");
        Assert.isTrue(AuthType.MFA_FORM.name().equalsIgnoreCase(firstConfiguredStep.getType()) || AuthType.MFA_REST.name().equalsIgnoreCase(firstConfiguredStep.getType()),
                "MFA flow must start with a MFA_FORM or MFA_REST primary authentication step. Current first step: " + firstConfiguredStep.getType());
        Assert.isTrue(configuredSteps.size() > 1, "MFA flow must have at least one secondary authentication factor.");

        if (primaryAuthOptionsForFlow == null) {
            Object firstStepRawOptions = firstConfiguredStep.getOptions().get("_options");
            if (firstStepRawOptions instanceof FormOptions fo) {
                
                primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder()
                    .formOptions(fo)
                    .loginProcessingUrl(fo.getLoginProcessingUrl())
                    .loginPage(fo.getLoginPage())           
                    .failureUrl(fo.getFailureUrl())         
                    .build();
            } else if (firstStepRawOptions instanceof RestOptions ro) {
                primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder()
                    .restOptions(ro)
                    .loginProcessingUrl(ro.getLoginProcessingUrl())
                    .build();
            } else {
                throw new DslConfigurationException("Could not determine PrimaryAuthenticationOptions from the first step of MFA flow. Step options type: " +
                        (firstStepRawOptions != null ? firstStepRawOptions.getClass().getName() : "null"));
            }
        }

        Assert.notNull(primaryAuthOptionsForFlow,
            "PrimaryAuthenticationOptions must not be null for MFA flow [" + this.mfaFlowTypeName + "]. " +
            "Either configure .primaryAuthentication() DSL or ensure the first step (order=0) has valid FormOptions or RestOptions.");

        Map<AuthType, AuthenticationProcessingOptions> factorOptionsMap = new LinkedHashMap<>();
        for (int i = 1; i < configuredSteps.size(); i++) {
            AuthenticationStepConfig step = configuredSteps.get(i);
            Object stepOptionsObject = step.getOptions().get("_options");
            if (!(stepOptionsObject instanceof AuthenticationProcessingOptions factorOption)) { 
                throw new DslConfigurationException("Options for MFA factor step '" + step.getType() +
                        "' are not of type AuthenticationProcessingOptions. Actual: " + (stepOptionsObject != null ? stepOptionsObject.getClass().getName() : "null"));
            }
            try {
                AuthType factorType = AuthType.valueOf(step.getType().toUpperCase());
                factorOptionsMap.put(factorType, factorOption);
            } catch (IllegalArgumentException e) {
                throw new DslConfigurationException("Invalid AuthType string for MFA factor stepConfig: " + step.getType(), e);
            }
        }

        MfaAuthenticationEntryPoint mfaAuthenticationEntryPoint = createMfaAuthenticationEntryPoint(primaryAuthOptionsForFlow);

        return flowConfigBuilder
                .typeName(this.mfaFlowTypeName)
                .order(this.order)
                .primaryAuthenticationOptions(primaryAuthOptionsForFlow)
                .stepConfigs(Collections.unmodifiableList(new ArrayList<>(this.configuredSteps)))
                .mfaPolicyProvider(this.policyProvider)
                .mfaFailureHandler(this.mfaFailureHandler)
                .finalSuccessHandler(this.finalSuccessHandler)
                .registeredFactorOptions(new LinkedHashMap<>(factorOptionsMap))
                .defaultDeviceTrustEnabled(this.defaultDeviceTrustEnabled)
                .mfaAsepAttributes(this.mfaAsepAttributes)
                .mfaPageConfig(this.mfaPageConfig)
                .mfaAuthenticationEntryPoint(mfaAuthenticationEntryPoint)
                .urlPrefix(this.urlPrefix)
                .build();
    }

    private MfaAuthenticationEntryPoint createMfaAuthenticationEntryPoint(PrimaryAuthenticationOptions primaryAuthOptions) {
        Assert.notNull(primaryAuthOptions, "PrimaryAuthenticationOptions cannot be null for creating MfaAuthenticationEntryPoint");

        String loginPageUrl = primaryAuthOptions.getLoginPage();

        if (!StringUtils.hasText(loginPageUrl)) {
            loginPageUrl = "/mfa/login";
            log.warn("loginPage not configured in PrimaryAuthenticationOptions. Using default: /mfa/login");
        }

        ObjectMapper objectMapper;
        try {
            objectMapper = this.applicationContext.getBean(ObjectMapper.class);
        } catch (Exception e) {
            throw new DslConfigurationException("Failed to retrieve ObjectMapper bean from ApplicationContext for MfaAuthenticationEntryPoint", e);
        }

        return new MfaAuthenticationEntryPoint(objectMapper, loginPageUrl, this.mfaPageConfig);
    }
}

