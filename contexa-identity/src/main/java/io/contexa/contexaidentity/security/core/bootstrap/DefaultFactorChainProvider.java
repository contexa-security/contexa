package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.adapter.auth.OttAuthenticationAdapter;
import io.contexa.contexaidentity.security.core.adapter.auth.PasskeyAuthenticationAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.configurer.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.OttConfigurerConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.PasskeyConfigurerConfigurer;
import io.contexa.contexaidentity.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class DefaultFactorChainProvider {

    private final ApplicationContext applicationContext;
    private final SecurityFilterChainRegistrar registrar;
    private final AdapterRegistry adapterRegistry;

    
    private static final Set<String> DEFAULT_FACTOR_TYPES = Set.of(
            AuthType.OTT.name().toLowerCase(),
            AuthType.PASSKEY.name().toLowerCase()
    );

    
    public void registerDefaultFactorChains(Set<String> configuredFactorTypes,
                                            BeanDefinitionRegistry registry,
                                            AtomicInteger idx) {
        
        if (!isMfaFlowConfigured()) {
            log.debug("No MFA flow configured, skipping default factor chain registration");
            return;
        }

        
        Set<String> missingFactorTypes = findMissingFactorTypes(configuredFactorTypes);

        if (missingFactorTypes.isEmpty()) {
            log.debug("All default factor types are already configured");
            return;
        }

        log.info("Creating default SecurityFilterChains for unconfigured factors: {}", missingFactorTypes);

        
        for (String factorType : missingFactorTypes) {
            registerDefaultFactorChain(factorType, registry, idx);
        }
    }

    
    private boolean isMfaFlowConfigured() {
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            return platformConfig != null && platformConfig.getFlows().stream()
                    .anyMatch(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()));
        } catch (Exception e) {
            log.debug("Failed to check for MFA flow configuration", e);
            return false;
        }
    }

    
    private Set<String> findMissingFactorTypes(Set<String> configuredFactorTypes) {
        return DEFAULT_FACTOR_TYPES.stream()
                .filter(type -> !configuredFactorTypes.contains(type))
                .collect(Collectors.toSet());
    }

    
    private void registerDefaultFactorChain(String factorType,
                                            BeanDefinitionRegistry registry,
                                            AtomicInteger idx) {
        try {
            
            FlowContext flowContext = createDefaultFlowContext(factorType);
            if (flowContext == null) {
                log.error("Failed to create default FlowContext for factor type: {}", factorType);
                return;
            }

            AuthenticationAdapter authenticationAdapter = adapterRegistry.getAuthenticationAdapter(factorType);
            if (authenticationAdapter instanceof PasskeyAuthenticationAdapter passkeyAdapter) {
                passkeyAdapter.apply(flowContext.http(), flowContext.flow().getStepConfigs(), flowContext.flow().getStateConfig());

            }else if(authenticationAdapter instanceof OttAuthenticationAdapter ottAdapter){
                ottAdapter.apply(flowContext.http(), flowContext.flow().getStepConfigs(), flowContext.flow().getStateConfig());
            }


            
            String beanName = "default" + capitalizeFirst(factorType) + "SecurityFilterChain" + idx.incrementAndGet();

            BeanDefinition bd = BeanDefinitionBuilder
                    .genericBeanDefinition(SecurityFilterChain.class,
                            () -> registrar.buildAndRegisterFilters(flowContext, applicationContext)) 
                    .setLazyInit(false)
                    .setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
                    .getBeanDefinition();

            registry.registerBeanDefinition(beanName, bd);
            log.info("Registered default SecurityFilterChain bean: {} for factor type: {}", beanName, factorType);

        } catch (Exception e) {
            log.error("Failed to create default SecurityFilterChain for factor type: {}", factorType, e);
        }
    }

    
    private FlowContext createDefaultFlowContext(String factorType) {
        log.debug("Creating default FlowContext for factor type: {}", factorType);

        try {
            PlatformContext platformContext = applicationContext.getBean(PlatformContext.class);
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);

            
            AuthenticationFlowConfig defaultFlowConfig = createDefaultFlowConfig(factorType);

            
            HttpSecurity http = platformContext.newHttp();

            
            if (platformConfig.getGlobalCustomizer() != null) {
                platformConfig.getGlobalCustomizer().customize(http);
            }

            
            applyDefaultFactorConfiguration(http, factorType);

            
            platformContext.registerHttp(defaultFlowConfig, http);

            
            http.setSharedObject(AuthenticationFlowConfig.class, defaultFlowConfig);
            http.setSharedObject(PlatformContext.class, platformContext);

            
            return new FlowContext(defaultFlowConfig, http, platformContext, platformConfig);

        } catch (Exception e) {
            log.error("Failed to create default FlowContext for factor type: {}", factorType, e);
            return null;
        }
    }

    
    private AuthenticationFlowConfig createDefaultFlowConfig(String factorType) {
        AuthType authType = AuthType.valueOf(factorType.toUpperCase());
        String flowTypeName = factorType + "_flow";

        
        String mfaFlowName = "mfa"; 
        int stepOrder = authType.ordinal() + 1; 

        
        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig(
                mfaFlowName,  
                authType.name(),
                stepOrder,    
                false         
        );

        
        AuthenticationProcessingOptions defaultOptions = createDefaultOptions(authType);
        stepConfig.getOptions().put("_options", defaultOptions);

        
        StateConfig stateConfig = new StateConfig(StateType.OAUTH2.name().toLowerCase(), StateType.OAUTH2);

        
        return AuthenticationFlowConfig.builder(flowTypeName)
                .order(1000 + authType.ordinal())  
                .stepConfigs(List.of(stepConfig))
                .stateConfig(stateConfig)
                .build();
    }

    
    private AuthenticationProcessingOptions createDefaultOptions(AuthType authType) {
        AuthMethodConfigurerFactory factory = new AuthMethodConfigurerFactory(applicationContext);

        switch (authType) {
            case OTT:
                return createDefaultOttOptions(factory);
            case PASSKEY:
                return createDefaultPasskeyOptions(factory);
            default:
                throw new IllegalArgumentException("Unsupported default factor type: " + authType);
        }
    }

    
    private AuthenticationProcessingOptions createDefaultOttOptions(AuthMethodConfigurerFactory factory) {
        try {
            var ottConfigurer = factory.createFactorConfigurer(AuthType.OTT,
                    OttConfigurerConfigurer.class);

            if (ottConfigurer instanceof AbstractOptionsBuilderConfigurer) {
                ((AbstractOptionsBuilderConfigurer<?, ?, ?, ?>) ottConfigurer)
                        .setApplicationContext(applicationContext);
            }

            
            ottConfigurer
                    .tokenGeneratingUrl("/api/ott/generate")
                    .loginProcessingUrl("/login/ott")
                    .tokenService(applicationContext.getBean(EmailOneTimeTokenService.class))
                    .successHandler(applicationContext.getBean("mfaFactorProcessingSuccessHandler",
                            PlatformAuthenticationSuccessHandler.class))
                    .failureHandler(applicationContext.getBean("unifiedAuthenticationFailureHandler",
                            PlatformAuthenticationFailureHandler.class));

            return ottConfigurer.buildConcreteOptions();

        } catch (Exception e) {
            log.error("Failed to create default OTT options with factory, creating manual configuration", e);
            
            throw new RuntimeException("Cannot create default OTT options", e);
        }
    }

    
    private AuthenticationProcessingOptions createDefaultPasskeyOptions(AuthMethodConfigurerFactory factory) {
        try {
            var passkeyConfigurer = factory.createFactorConfigurer(AuthType.PASSKEY, PasskeyConfigurerConfigurer.class);

            if (passkeyConfigurer instanceof AbstractOptionsBuilderConfigurer) {
                ((AbstractOptionsBuilderConfigurer<?, ?, ?, ?>) passkeyConfigurer).setApplicationContext(applicationContext);
            }

            String rpId = applicationContext.getEnvironment()
                    .getProperty("spring.security.webauthn.relyingparty.id", "localhost");
            String rpName = applicationContext.getEnvironment()
                    .getProperty("spring.security.webauthn.relyingparty.name", "Spring Security Platform");

            
            passkeyConfigurer
                    .rpId(rpId)
                    .rpName(rpName)
                    .loginProcessingUrl("/login/passkey")
                    .assertionOptionsEndpoint("/webauthn/assertion/options")
                    .successHandler(applicationContext.getBean("mfaFactorProcessingSuccessHandler", PlatformAuthenticationSuccessHandler.class))
                    .failureHandler(applicationContext.getBean("unifiedAuthenticationFailureHandler", PlatformAuthenticationFailureHandler.class));

            return passkeyConfigurer.buildConcreteOptions();

        } catch (Exception e) {
            log.error("Failed to create default Passkey options with factory", e);
            throw new RuntimeException("Cannot create default Passkey options", e);
        }
    }

    
    private void applyDefaultFactorConfiguration(HttpSecurity http, String factorType) {
        try {
            switch (factorType.toLowerCase()) {
                case "ott":
                    http.authorizeHttpRequests(auth -> auth
                            .requestMatchers("/api/ott/**", "/login/ott", "/ott/sent").permitAll()
                    );
                    break;

                case "passkey":
                    http.authorizeHttpRequests(auth -> auth
                            .requestMatchers("/webauthn/**", "/login/passkey").permitAll()
                    );
                    break;
            }
        } catch (Exception e) {
            log.error("Failed to apply default configuration for factor: {}", factorType, e);
        }
    }

    
    private String capitalizeFirst(String str) {
        if (str == null || str.isEmpty()) {
            return str;
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1);
    }
}