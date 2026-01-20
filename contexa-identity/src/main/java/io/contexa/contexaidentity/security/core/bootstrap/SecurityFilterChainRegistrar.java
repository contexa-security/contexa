package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import io.contexa.contexaidentity.security.core.mfa.context.FactorIdentifier;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexaidentity.security.handler.*;
import io.contexa.contexacommon.properties.AuthContextProperties;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;


@Slf4j
public class SecurityFilterChainRegistrar {
    private final ConfiguredFactorFilterProvider configuredFactorFilterProvider;
    private final Map<String, Class<? extends Filter>> stepFilterClasses;
    private final AdapterRegistry adapterRegistry;

    
    private static final Set<String> DEFAULT_FACTOR_TYPES = Set.of(
            AuthType.OTT.name().toLowerCase(),
            AuthType.PASSKEY.name().toLowerCase()
    );

    public SecurityFilterChainRegistrar(ConfiguredFactorFilterProvider configuredFactorFilterProvider,
                                        Map<String, Class<? extends Filter>> stepFilterClasses, AdapterRegistry adapterRegistry) {
        this.configuredFactorFilterProvider = Objects.requireNonNull(configuredFactorFilterProvider, "ConfiguredFactorFilterProvider cannot be null.");
        this.stepFilterClasses  = Objects.requireNonNull(stepFilterClasses, "stepFilterClasses cannot be null.");
        this.adapterRegistry = adapterRegistry;
    }

    public void registerSecurityFilterChains(List<FlowContext> flows, ApplicationContext context) {
        Assert.notNull(flows, "Flows list cannot be null.");
        Assert.notNull(context, "ApplicationContext cannot be null.");

        if (!(context instanceof ConfigurableApplicationContext cac)) {
            log.warn("ApplicationContext is not a ConfigurableApplicationContext. Cannot register SecurityFilterChain beans dynamically.");
            return;
        }
        BeanDefinitionRegistry registry = (BeanDefinitionRegistry) cac.getBeanFactory();
        AtomicInteger idx = new AtomicInteger(0);

        
        Set<String> configuredFactorTypes = new HashSet<>();

        for (FlowContext fc : flows) {
            Objects.requireNonNull(fc, "FlowContext in list cannot be null.");
            AuthenticationFlowConfig flowConfig = Objects.requireNonNull(fc.flow(), "AuthenticationFlowConfig in FlowContext cannot be null.");
            String flowTypeName = Objects.requireNonNull(flowConfig.getTypeName(), "Flow typeName cannot be null.");

            
            if (AuthType.MFA.name().equalsIgnoreCase(flowTypeName)) {
                flowConfig.getStepConfigs().stream()
                        .map(step -> step.getType().toLowerCase())
                        .filter(type -> !type.equals("primary"))
                        .forEach(configuredFactorTypes::add);
            }

            String beanName = flowTypeName + "SecurityFilterChain" + idx.incrementAndGet();
            OrderedSecurityFilterChain chain = buildAndRegisterFilters(fc, context);
            BeanDefinition bd = BeanDefinitionBuilder
                    .genericBeanDefinition(SecurityFilterChain.class, () -> chain)
                    .setLazyInit(false)
                    .setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
                    .getBeanDefinition();
            registry.registerBeanDefinition(beanName, bd);
            log.info("Registered SecurityFilterChain bean: {} for flow type: {}", beanName, flowTypeName);
        }
        
        DefaultFactorChainProvider defaultProvider = new DefaultFactorChainProvider(context, this, adapterRegistry); 


    }

    
    public OrderedSecurityFilterChain buildAndRegisterFilters(FlowContext fc, ApplicationContext appContext) {
        try {
            AuthenticationFlowConfig flowConfig = fc.flow();
            log.debug("Building SecurityFilterChain and registering factor filters for flow: type='{}', order={}",
                    flowConfig.getTypeName(), flowConfig.getOrder());

            DefaultSecurityFilterChain builtChain = fc.http().build();
            log.debug("Successfully built DefaultSecurityFilterChain for flow: {}", flowConfig.getTypeName());

            replaceWebAuthnHandlersIfNeeded(builtChain, flowConfig, appContext);

            for (AuthenticationStepConfig step : flowConfig.getStepConfigs()) {
                Objects.requireNonNull(step, "AuthenticationStepConfig in flow cannot be null.");
                String pureFactorType = Objects.requireNonNull(step.getType(), "Step type cannot be null.").toLowerCase();
                String stepId = step.getStepId();

                if (!StringUtils.hasText(stepId)) {
                    log.error("CRITICAL: AuthenticationStepConfig (type: {}, order: {}) in flow '{}' is missing a stepId. " +
                                    "This step's filter cannot be registered in ConfiguredFactorFilterProvider.",
                            pureFactorType, step.getOrder(), flowConfig.getTypeName());
                    continue;
                }

                
                if (AuthType.MFA.name().equalsIgnoreCase(flowConfig.getTypeName()) && step.getOrder() == 0) {
                    log.trace("Skipping filter registration for primary auth step '{}' (id: {}) in MFA flow '{}'",
                            pureFactorType, stepId, flowConfig.getTypeName());
                    continue;
                }

                Class<? extends Filter> filterClass = stepFilterClasses.get(pureFactorType);
                if (filterClass == null) {
                    log.error("No filter class configured in stepFilterClasses for step type: '{}' (id: {}) in flow: '{}'",
                            pureFactorType, stepId, flowConfig.getTypeName());
                    throw new IllegalStateException("필터 클래스 미설정: " + pureFactorType + " (flow: " + flowConfig.getTypeName() + ")");
                }

                Optional<Filter> foundFilterOptional = builtChain.getFilters().stream()
                        .filter(filterClass::isInstance)
                        .findFirst();

                if (foundFilterOptional.isEmpty()) {
                    log.error("Filter of type {} not found in the built SecurityFilterChain for step: '{}' in flow: '{}'. Critical configuration error.",
                            filterClass.getName(), stepId, flowConfig.getTypeName());
                    throw new IllegalStateException("빌드된 체인에서 필터 인스턴스를 찾을 수 없습니다: " + stepId + " (flow: " + flowConfig.getTypeName() + ")");
                }

                Filter actualFilterInstance = foundFilterOptional.get();
                
                FactorIdentifier registrationKey = FactorIdentifier.of(flowConfig.getTypeName(), stepId);

                configuredFactorFilterProvider.registerFilter(registrationKey, actualFilterInstance);
            }

            return new OrderedSecurityFilterChain(
                    Ordered.HIGHEST_PRECEDENCE + flowConfig.getOrder(),
                    builtChain.getRequestMatcher(),
                    builtChain.getFilters()
            );
        } catch (Exception e) {
            log.error("Error building SecurityFilterChain or registering factor filters for flow: {}", fc.flow().getTypeName(), e);
            throw new RuntimeException("Failed to build SecurityFilterChain for flow " + fc.flow().getTypeName(), e);
        }
    }

    
    private void replaceWebAuthnHandlersIfNeeded(DefaultSecurityFilterChain builtChain,
                                                  AuthenticationFlowConfig flowConfig,
                                                  ApplicationContext appContext) {
        
        AuthenticationStepConfig passkeyStep = flowConfig.getStepConfigs().stream()
                .filter(step -> AuthType.PASSKEY.name().equalsIgnoreCase(step.getType()) ||
                               AuthType.MFA_PASSKEY.name().equalsIgnoreCase(step.getType()))
                .findFirst()
                .orElse(null);

        if (passkeyStep == null) {
            return;
        }

        boolean isMfaFlow = AuthType.MFA.name().equalsIgnoreCase(flowConfig.getTypeName());

        for (Filter filter : builtChain.getFilters()) {
            if (filter instanceof AbstractAuthenticationProcessingFilter authFilter) {
                String filterClassName = filter.getClass().getSimpleName();

                if (filterClassName.contains("WebAuthn")) {
                    try {
                        
                        AuthContextProperties authProps = appContext.getBean(AuthContextProperties.class);
                        StateType stateType = (flowConfig.getStateConfig() != null && flowConfig.getStateConfig().stateType() != null) ?
                                flowConfig.getStateConfig().stateType() : authProps.getStateType();

                        
                        PlatformAuthenticationSuccessHandler customSuccessHandler = null;
                        PlatformAuthenticationFailureHandler customFailureHandler = null;

                        if (isMfaFlow) {
                            
                            if (stateType == StateType.SESSION) {
                                customSuccessHandler = appContext.getBean(SessionMfaSuccessHandler.class);
                                customFailureHandler = appContext.getBean(SessionMfaFailureHandler.class);
                                log.debug("MFA Passkey + SESSION: Using SessionMfa* handlers");
                            } else {
                                
                                customSuccessHandler = appContext.getBean(MfaFactorProcessingSuccessHandler.class);
                                customFailureHandler = appContext.getBean(UnifiedAuthenticationFailureHandler.class);
                                log.debug("MFA Passkey + OAuth2/JWT: Using MfaFactorProcessing* + Unified* handlers");
                            }
                        } else {
                            
                            if (stateType == StateType.SESSION) {
                                
                                customSuccessHandler = null;
                                customFailureHandler = null;
                                log.debug("Single Passkey + SESSION: Using Spring Security default handlers (null)");
                            } else {
                                
                                customSuccessHandler = appContext.getBean(OAuth2SingleAuthSuccessHandler.class);
                                customFailureHandler = appContext.getBean(OAuth2SingleAuthFailureHandler.class);
                                log.debug("Single Passkey + OAuth2/JWT: Using OAuth2SingleAuth* handlers");
                            }
                        }

                        
                        if (customSuccessHandler != null) {
                            authFilter.setAuthenticationSuccessHandler(customSuccessHandler);
                        }
                        if (customFailureHandler != null) {
                            authFilter.setAuthenticationFailureHandler(customFailureHandler);
                        }

                        
                        if (isMfaFlow) {
                            String customLoginProcessingUrl = authProps.getUrls().getFactors().getPasskey().getLoginProcessing();
                            if (customLoginProcessingUrl != null && !customLoginProcessingUrl.isEmpty()) {
                                RequestMatcher customMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, customLoginProcessingUrl);
                                authFilter.setRequiresAuthenticationRequestMatcher(customMatcher);
                                log.info("WebAuthn loginProcessingUrl changed to: {}", customLoginProcessingUrl);
                            }
                        }

                        log.info("WebAuthnAuthenticationFilter handlers replacement completed for flow: {}, StateType: {}, MFA: {}",
                                flowConfig.getTypeName(), stateType, isMfaFlow);

                        return;

                    } catch (Exception e) {
                        log.error("Failed to replace WebAuthn handlers for flow: {}", flowConfig.getTypeName(), e);
                    }
                }
            }
        }

        log.warn("⚠️ WebAuthnAuthenticationFilter not found in filter chain for flow: {}. " +
                "Passkey authentication may not work properly without custom handlers.",
                flowConfig.getTypeName());
    }
}




