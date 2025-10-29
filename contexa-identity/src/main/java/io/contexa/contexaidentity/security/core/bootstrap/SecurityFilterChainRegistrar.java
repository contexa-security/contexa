package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import io.contexa.contexaidentity.security.core.mfa.context.FactorIdentifier;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.handler.MfaFactorProcessingSuccessHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.handler.PrimaryAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.handler.UnifiedAuthenticationFailureHandler;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecurityFilterChainRegistrar 리팩토링 버전
 * - stepToFilter를 Class가 아닌 실제 Filter 인스턴스 맵으로 주입
 * - buildChain 책임 분리
 * - BeanDefinition 생성 로직 분리로 가독성 향상
 */
@Slf4j
public class SecurityFilterChainRegistrar {
    private final ConfiguredFactorFilterProvider configuredFactorFilterProvider;
    private final Map<String, Class<? extends Filter>> stepFilterClasses;
    private final AdapterRegistry adapterRegistry;

    // 기본 팩터 타입들 정의
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

        // 1. 명시적으로 설정된 팩터들 먼저 등록
        Set<String> configuredFactorTypes = new HashSet<>();

        for (FlowContext fc : flows) {
            Objects.requireNonNull(fc, "FlowContext in list cannot be null.");
            AuthenticationFlowConfig flowConfig = Objects.requireNonNull(fc.flow(), "AuthenticationFlowConfig in FlowContext cannot be null.");
            String flowTypeName = Objects.requireNonNull(flowConfig.getTypeName(), "Flow typeName cannot be null.");

            // 설정된 팩터 타입 수집
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
        // 2. 설정되지 않은 기본 팩터들에 대한 SecurityFilterChain 생성
        DefaultFactorChainProvider defaultProvider = new DefaultFactorChainProvider(context, this, adapterRegistry); // this 전달
        defaultProvider.registerDefaultFactorChains(configuredFactorTypes, registry, idx);

    }

    // 메소드명 변경 및 fc를 인자로 받음
    public OrderedSecurityFilterChain buildAndRegisterFilters(FlowContext fc, ApplicationContext appContext) {
        try {
            AuthenticationFlowConfig flowConfig = fc.flow();
            log.debug("Building SecurityFilterChain and registering factor filters for flow: type='{}', order={}",
                    flowConfig.getTypeName(), flowConfig.getOrder());

            DefaultSecurityFilterChain builtChain = fc.http().build();
            log.debug("Successfully built DefaultSecurityFilterChain for flow: {}", flowConfig.getTypeName());

            // ⭐ Passkey (WebAuthn) 핸들러 교체: Spring Security WebAuthn DSL이 커스텀 핸들러 등록을 지원하지 않으므로
            // Filter Chain 빌드 후 WebAuthnAuthenticationFilter를 찾아서 핸들러를 교체합니다.
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

                // 1차 인증 스텝은 MfaStepFilterWrapper의 위임 대상이 아니므로 등록 불필요
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
                // FactorIdentifier 생성: flowConfig의 typeName과 step의 stepId 사용
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

    /**
     * Passkey (WebAuthn) 인증 핸들러 교체
     *
     * <p>
     * Spring Security의 WebAuthn DSL은 커스텀 Success/Failure Handler 등록 API를 제공하지 않습니다.
     * WebAuthnAuthenticationFilter 생성자에서 기본 핸들러를 설정하기 때문입니다:
     * <ul>
     *   <li>Success: HttpMessageConverterAuthenticationSuccessHandler (토큰 발급 없음)</li>
     *   <li>Failure: AuthenticationEntryPointFailureHandler</li>
     * </ul>
     * </p>
     *
     * <p>
     * 하지만 AbstractAuthenticationProcessingFilter의 setter는 public이므로,
     * Filter Chain 빌드 후 WebAuthnAuthenticationFilter를 찾아서 우리의 커스텀 핸들러로 교체합니다.
     * </p>
     *
     * <p>
     * 이를 통해:
     * <ul>
     *   <li>MFA State Machine 자동 통합</li>
     *   <li>OAuth2 토큰 자동 발급</li>
     *   <li>OTT와 동일한 인증 플로우</li>
     * </ul>
     * 를 구현합니다.
     * </p>
     *
     * @param builtChain 빌드된 SecurityFilterChain
     * @param flowConfig 현재 Flow 설정
     * @param appContext Spring ApplicationContext for retrieving handler beans
     */
    private void replaceWebAuthnHandlersIfNeeded(DefaultSecurityFilterChain builtChain,
                                                  AuthenticationFlowConfig flowConfig,
                                                  ApplicationContext appContext) {
        // Passkey 스텝이 있는지 확인
        boolean hasPasskeyStep = flowConfig.getStepConfigs().stream()
                .anyMatch(step -> AuthType.PASSKEY.name().equalsIgnoreCase(step.getType()));

        if (!hasPasskeyStep) {
            return; // Passkey 스텝이 없으면 처리 불필요
        }

        log.debug("🔧 Passkey step detected in flow '{}', searching for WebAuthnAuthenticationFilter...",
                flowConfig.getTypeName());

        // Filter Chain에서 WebAuthnAuthenticationFilter 찾기
        for (Filter filter : builtChain.getFilters()) {
            // AbstractAuthenticationProcessingFilter를 상속한 필터 중에서
            if (filter instanceof AbstractAuthenticationProcessingFilter) {
                AbstractAuthenticationProcessingFilter authFilter =
                    (AbstractAuthenticationProcessingFilter) filter;

                // 클래스 이름으로 WebAuthnAuthenticationFilter 식별
                String filterClassName = filter.getClass().getSimpleName();
                if (filterClassName.contains("WebAuthn")) {
                    log.info("🔧 Found WebAuthnAuthenticationFilter, replacing handlers...");

                    // Passkey 스텝 찾기
                    AuthenticationStepConfig passkeyStep = flowConfig.getStepConfigs().stream()
                            .filter(step -> AuthType.PASSKEY.name().equalsIgnoreCase(step.getType()))
                            .findFirst()
                            .orElse(null);

                    if (passkeyStep == null) {
                        log.warn("⚠️ Passkey step configuration not found, cannot replace handlers");
                        return;
                    }

                    // Success Handler 결정: Spring Bean으로부터 가져오기
                    // MFA Flow에서 Passkey는 intermediate factor이므로 MfaFactorProcessingSuccessHandler 사용
                    PlatformAuthenticationSuccessHandler customSuccessHandler;
                    if ("mfa".equalsIgnoreCase(flowConfig.getTypeName())) {
                        // MFA Flow: Passkey는 secondary factor이므로 MfaFactorProcessingSuccessHandler
                        try {
                            customSuccessHandler = appContext.getBean(MfaFactorProcessingSuccessHandler.class);
                            log.debug("Using MfaFactorProcessingSuccessHandler for Passkey in MFA flow");
                        } catch (Exception e) {
                            log.error(" Failed to retrieve MfaFactorProcessingSuccessHandler bean from ApplicationContext", e);
                            return;
                        }
                    } else {
                        // Single Flow: PrimaryAuthenticationSuccessHandler
                        try {
                            customSuccessHandler = appContext.getBean(PrimaryAuthenticationSuccessHandler.class);
                            log.debug("Using PrimaryAuthenticationSuccessHandler for Passkey in single flow");
                        } catch (Exception e) {
                            log.error(" Failed to retrieve PrimaryAuthenticationSuccessHandler bean from ApplicationContext", e);
                            return;
                        }
                    }

                    // Failure Handler 결정: Spring Bean으로부터 가져오기
                    PlatformAuthenticationFailureHandler customFailureHandler;
                    try {
                        customFailureHandler = appContext.getBean(UnifiedAuthenticationFailureHandler.class);
                        log.debug("Using UnifiedAuthenticationFailureHandler for Passkey");
                    } catch (Exception e) {
                        log.error(" Failed to retrieve UnifiedAuthenticationFailureHandler bean from ApplicationContext", e);
                        return;
                    }

                    // 핸들러 교체
                    authFilter.setAuthenticationSuccessHandler(customSuccessHandler);
                    log.info("WebAuthn Success Handler replaced: {}",
                            customSuccessHandler.getClass().getSimpleName());

                    authFilter.setAuthenticationFailureHandler(customFailureHandler);
                    log.info("WebAuthn Failure Handler replaced: {}",
                            customFailureHandler.getClass().getSimpleName());

                    log.info("WebAuthnAuthenticationFilter handlers replacement completed for flow: {}",
                            flowConfig.getTypeName());

                    return; // 찾았으면 종료
                }
            }
        }

        log.warn("⚠️ WebAuthnAuthenticationFilter not found in filter chain for flow: {}. " +
                "Passkey authentication may not work properly without custom handlers.",
                flowConfig.getTypeName());
    }
}




