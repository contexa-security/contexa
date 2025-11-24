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

/**
 * 설정되지 않은 기본 MFA 팩터들에 대한 SecurityFilterChain을 생성하고 등록하는 클래스
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultFactorChainProvider {

    private final ApplicationContext applicationContext;
    private final SecurityFilterChainRegistrar registrar;
    private final AdapterRegistry adapterRegistry;

    // 기본 팩터 타입들 정의
    private static final Set<String> DEFAULT_FACTOR_TYPES = Set.of(
            AuthType.OTT.name().toLowerCase(),
            AuthType.PASSKEY.name().toLowerCase()
    );

    /**
     * 설정되지 않은 기본 팩터들에 대한 SecurityFilterChain 등록
     */
    public void registerDefaultFactorChains(Set<String> configuredFactorTypes,
                                            BeanDefinitionRegistry registry,
                                            AtomicInteger idx) {
        // MFA 플로우가 설정되었는지 확인
        if (!isMfaFlowConfigured()) {
            log.debug("No MFA flow configured, skipping default factor chain registration");
            return;
        }

        // 설정되지 않은 기본 팩터들 찾기
        Set<String> missingFactorTypes = findMissingFactorTypes(configuredFactorTypes);

        if (missingFactorTypes.isEmpty()) {
            log.debug("All default factor types are already configured");
            return;
        }

        log.info("Creating default SecurityFilterChains for unconfigured factors: {}", missingFactorTypes);

        // 각 미설정 팩터에 대해 기본 SecurityFilterChain 생성 및 등록
        for (String factorType : missingFactorTypes) {
            registerDefaultFactorChain(factorType, registry, idx);
        }
    }

    /**
     * MFA 플로우가 설정되었는지 확인
     */
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

    /**
     * 설정되지 않은 팩터 타입들 찾기
     */
    private Set<String> findMissingFactorTypes(Set<String> configuredFactorTypes) {
        return DEFAULT_FACTOR_TYPES.stream()
                .filter(type -> !configuredFactorTypes.contains(type))
                .collect(Collectors.toSet());
    }

    /**
     * 개별 팩터에 대한 기본 SecurityFilterChain 등록
     */
    private void registerDefaultFactorChain(String factorType,
                                            BeanDefinitionRegistry registry,
                                            AtomicInteger idx) {
        try {
            // 기본 FlowContext 생성
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


            // SecurityFilterChainRegistrar의 buildAndRegisterFilters 메서드 사용
            String beanName = "default" + capitalizeFirst(factorType) + "SecurityFilterChain" + idx.incrementAndGet();

            BeanDefinition bd = BeanDefinitionBuilder
                    .genericBeanDefinition(SecurityFilterChain.class,
                            () -> registrar.buildAndRegisterFilters(flowContext, applicationContext)) // registrar 사용
                    .setLazyInit(false)
                    .setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
                    .getBeanDefinition();

            registry.registerBeanDefinition(beanName, bd);
            log.info("Registered default SecurityFilterChain bean: {} for factor type: {}", beanName, factorType);

        } catch (Exception e) {
            log.error("Failed to create default SecurityFilterChain for factor type: {}", factorType, e);
        }
    }

    /**
     * 기본 FlowContext 생성
     */
    private FlowContext createDefaultFlowContext(String factorType) {
        log.debug("Creating default FlowContext for factor type: {}", factorType);

        try {
            PlatformContext platformContext = applicationContext.getBean(PlatformContext.class);
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);

            // 기본 AuthenticationFlowConfig 생성
            AuthenticationFlowConfig defaultFlowConfig = createDefaultFlowConfig(factorType);

            // HttpSecurity 인스턴스 생성
            HttpSecurity http = platformContext.newHttp();

            // 전역 설정 적용
            if (platformConfig.getGlobalCustomizer() != null) {
                platformConfig.getGlobalCustomizer().customize(http);
            }

            // 팩터별 기본 설정 적용
            applyDefaultFactorConfiguration(http, factorType);

            // HttpSecurity에 FlowConfig 등록
            platformContext.registerHttp(defaultFlowConfig, http);

            // HttpSecurity에 공유 객체 설정
            http.setSharedObject(AuthenticationFlowConfig.class, defaultFlowConfig);
            http.setSharedObject(PlatformContext.class, platformContext);

            // FlowContext 생성
            return new FlowContext(defaultFlowConfig, http, platformContext, platformConfig);

        } catch (Exception e) {
            log.error("Failed to create default FlowContext for factor type: {}", factorType, e);
            return null;
        }
    }

    /**
     * 기본 AuthenticationFlowConfig 생성
     */
    private AuthenticationFlowConfig createDefaultFlowConfig(String factorType) {
        AuthType authType = AuthType.valueOf(factorType.toUpperCase());
        String flowTypeName = factorType + "_flow";

        // MFA 플로우의 일부로 동작할 수 있도록 stepId 생성
        String mfaFlowName = "mfa"; // MFA 플로우 이름
        int stepOrder = authType.ordinal() + 1; // OTT=1, PASSKEY=2 등

        // 기본 AuthenticationStepConfig 생성
        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig(
                mfaFlowName,  // MFA 플로우의 일부로 stepId 생성
                authType.name(),
                stepOrder,    // MFA 내에서의 순서
                false         // isPrimary = false
        );

        // 기본 옵션 설정
        AuthenticationProcessingOptions defaultOptions = createDefaultOptions(authType);
        stepConfig.getOptions().put("_options", defaultOptions);

        // StateConfig 생성 (기본은 OAUTH2)
        StateConfig stateConfig = new StateConfig(StateType.OAUTH2.name().toLowerCase(), StateType.OAUTH2);

        // AuthenticationFlowConfig 빌드
        return AuthenticationFlowConfig.builder(flowTypeName)
                .order(1000 + authType.ordinal())  // 기본 팩터는 낮은 우선순위
                .stepConfigs(List.of(stepConfig))
                .stateConfig(stateConfig)
                .build();
    }

    /**
     * 팩터 타입별 기본 옵션 생성
     */
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

    /**
     * 기본 OTT 옵션 생성
     */
    private AuthenticationProcessingOptions createDefaultOttOptions(AuthMethodConfigurerFactory factory) {
        try {
            var ottConfigurer = factory.createFactorConfigurer(AuthType.OTT,
                    OttConfigurerConfigurer.class);

            if (ottConfigurer instanceof AbstractOptionsBuilderConfigurer) {
                ((AbstractOptionsBuilderConfigurer<?, ?, ?, ?>) ottConfigurer)
                        .setApplicationContext(applicationContext);
            }

            // 기본 OTT 설정
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
            // Factory 실패시 수동으로 기본 OttOptions 생성
            throw new RuntimeException("Cannot create default OTT options", e);
        }
    }

    /**
     * 기본 Passkey 옵션 생성
     */
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

            // 기본 Passkey 설정
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

    /**
     * 팩터별 기본 HTTP 설정 적용
     */
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

    /**
     * 첫 글자를 대문자로 변환
     */
    private String capitalizeFirst(String str) {
        if (str == null || str.isEmpty()) {
            return str;
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1);
    }
}