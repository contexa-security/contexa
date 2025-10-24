package io.contexa.contexaidentity.security.core.dsl;

import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateConfigurer;
import io.contexa.contexaidentity.security.core.adapter.state.session.SessionStateConfigurer;
import io.contexa.contexaidentity.security.core.asep.dsl.BaseAsepAttributes;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.AuthenticationFactorConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.MfaDslConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.impl.MfaDslConfigurerImpl;
import io.contexa.contexaidentity.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.enums.StateType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

import java.util.List;
import java.util.Objects;

@Slf4j
public abstract class AbstractFlowRegistrar<H extends HttpSecurityBuilder<H>> implements IdentityAuthDsl {

    protected final PlatformConfig.Builder platformBuilder;
    private final StateSetter stateSetter;
    protected final ApplicationContext applicationContext;
    private final AuthMethodConfigurerFactory authMethodConfigurerFactory;

    protected AbstractFlowRegistrar(PlatformConfig.Builder platformBuilder,
                                    ApplicationContext applicationContext) {
        this.platformBuilder = Objects.requireNonNull(platformBuilder, "platformBuilder cannot be null");
        this.applicationContext = Objects.requireNonNull(applicationContext, "applicationContext cannot be null");
        this.stateSetter = new StateSetter();
        this.authMethodConfigurerFactory = new AuthMethodConfigurerFactory(this.applicationContext);
    }

    protected <O extends AuthenticationProcessingOptions,
            A extends BaseAsepAttributes,
            S extends AuthenticationFactorConfigurer<O, A, S>> IdentityStateDsl registerAuthenticationMethod(
            AuthType authType, // 순수 Factor 타입 (예: FORM, OTT)
            Customizer<S> configurerCustomizer,
            int defaultOrder,
            Class<S> configurerInterfaceType) {

        S configurer = authMethodConfigurerFactory.createFactorConfigurer(
                authType,
                configurerInterfaceType
        );

        if (configurer instanceof AbstractOptionsBuilderConfigurer builderConfigurer) {
            builderConfigurer.setApplicationContext(this.applicationContext);
        }

        Objects.requireNonNull(configurerCustomizer, "configurerCustomizer cannot be null").customize(configurer);
        O options = configurer.buildConcreteOptions();

        int actualOrder = defaultOrder;
        if (options.getOrder() != 0) { // AuthenticationProcessingOptions 에서 getOrder() 사용
            actualOrder = options.getOrder();
        }

        // 단일 인증 플로우의 typeName은 authType.name()을 기반으로 생성 (예: "form_login", "ott_email")
        // 또는 더 구체적인 이름을 사용자가 DSL 에서 지정할 수 있도록 확장 가능
        String flowTypeName = authType.name().toLowerCase() + "_flow"; // 예시: "form_flow"
        String finalFlowTypeName = flowTypeName;
        if (platformBuilder.getModifiableFlows().stream().anyMatch(f -> f.getTypeName().equalsIgnoreCase(finalFlowTypeName))) {
            String finalFlowTypeName1 = flowTypeName;
            long count = platformBuilder.getModifiableFlows().stream().filter(f -> f.getTypeName().startsWith(finalFlowTypeName1)).count();
            flowTypeName = flowTypeName + "_" + (count + 1);
        }


        // AuthenticationStepConfig 생성 시 flowTypeName, authType.name(), actualOrder 전달
        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig(flowTypeName, authType.name(), actualOrder, false);
        stepConfig.getOptions().put("_options", options);
        // stepConfig.setOrder(actualOrder); // 생성자에서 설정됨

        AuthenticationFlowConfig.Builder flowBuilder = AuthenticationFlowConfig.builder(flowTypeName)
                .stepConfigs(List.of(stepConfig))
                .stateConfig(null) // 상태는 이후 .jwt(), .session() 등으로 설정됨
                .order(actualOrder);

        // AuthenticationProcessingOptions에서 successHandler, failureHandler를 가져와 FlowConfig에 설정 (선택적)
        if (options.getSuccessHandler() != null) {
            flowBuilder.finalSuccessHandler(options.getSuccessHandler()); // 단일 스텝 플로우이므로 finalSuccessHandler로 간주
        }
        // if (options.getFailureHandler() != null) {
        //     // flowBuilder.mfaFailureHandler(options.getFailureHandler()); // 단일 인증에는 mfaFailureHandler가 아님.
        //     // 필요시 AuthenticationFlowConfig에 일반 failureHandler 필드 추가
        // }


        platformBuilder.addFlow(flowBuilder.build());
        log.info("AbstractFlowRegistrar: Registered single-step authentication flow: '{}' (stepId: '{}'), Order: {}",
                flowTypeName, stepConfig.getStepId(), actualOrder);
        return this.stateSetter;
    }

    protected IdentityStateDsl registerMultiStepFlow(
            Customizer<MfaDslConfigurer> customizer) {
        MfaDslConfigurerImpl<H> mfaDslConfigurer =
                authMethodConfigurerFactory.createMfaConfigurer(this.applicationContext);
        Objects.requireNonNull(customizer, "mfa customizer cannot be null").customize(mfaDslConfigurer);
        AuthenticationFlowConfig mfaFlow = mfaDslConfigurer.build(); // 이 내부에서 stepId들이 설정됨

        platformBuilder.addFlow(mfaFlow);
        log.info("AbstractFlowRegistrar: Registered MFA flow options. Flow TypeName: '{}', Order: {}. Steps: {}",
                mfaFlow.getTypeName(), mfaFlow.getOrder(), mfaFlow.getStepConfigs().size());
        return this.stateSetter;
    }

    private final class StateSetter implements IdentityStateDsl {
        private void replaceLastState(StateType stateType) {
            List<AuthenticationFlowConfig> currentFlows = platformBuilder.getModifiableFlows();
            if (currentFlows.isEmpty()) {
                log.warn("AbstractFlowRegistrar.StateSetter: No flow to replace state for. State type '{}' will not be applied.", stateType);
                return;
            }
            int lastIndex = currentFlows.size() - 1;
            AuthenticationFlowConfig lastFlow = currentFlows.get(lastIndex);
            AuthenticationFlowConfig updatedFlow = lastFlow.withStateConfig(new StateConfig(stateType.name().toLowerCase(), stateType));
            currentFlows.set(lastIndex, updatedFlow);
            log.debug("AbstractFlowRegistrar.StateSetter: Set state for last flow (type: {}) to: {}",
                    lastFlow.getTypeName(), stateType);
        }

        @Override
        public IdentityAuthDsl session(Customizer<SessionStateConfigurer> customizer) {
            replaceLastState(StateType.SESSION);
            return AbstractFlowRegistrar.this;
        }

        @Override
        public IdentityAuthDsl oauth2(Customizer<OAuth2StateConfigurer> customizer) {
            replaceLastState(StateType.OAUTH2);
            return AbstractFlowRegistrar.this;
        }
    }
}