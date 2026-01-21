package io.contexa.contexaidentity.security.core.dsl;

import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateConfigurer;
import io.contexa.contexaidentity.security.core.adapter.state.session.SessionStateConfigurer;
import io.contexa.contexaidentity.security.core.asep.dsl.BaseAsepAttributes;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.dsl.configurer.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.AuthenticationFactorConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.MfaDslConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.impl.MfaDslConfigurerImpl;
import io.contexa.contexaidentity.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
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
            AuthType authType, 
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
        if (options.getOrder() != 0) { 
            actualOrder = options.getOrder();
        }

        String flowTypeName = authType.name().toLowerCase() + "_flow"; 
        String finalFlowTypeName = flowTypeName;
        if (platformBuilder.getModifiableFlows().stream().anyMatch(f -> f.getTypeName().equalsIgnoreCase(finalFlowTypeName))) {
            String finalFlowTypeName1 = flowTypeName;
            long count = platformBuilder.getModifiableFlows().stream().filter(f -> f.getTypeName().startsWith(finalFlowTypeName1)).count();
            flowTypeName = flowTypeName + "_" + (count + 1);
        }

        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig(flowTypeName, authType.name(), actualOrder, false);
        stepConfig.getOptions().put("_options", options);

        AuthenticationFlowConfig.Builder flowBuilder = AuthenticationFlowConfig.builder(flowTypeName)
                .stepConfigs(List.of(stepConfig))
                .stateConfig(null) 
                .order(actualOrder);

        if (options.getSuccessHandler() != null) {
            flowBuilder.finalSuccessHandler(options.getSuccessHandler()); 
        }

        platformBuilder.addFlow(flowBuilder.build());
                return this.stateSetter;
    }

    protected IdentityStateDsl registerMultiStepFlow(
            Customizer<MfaDslConfigurer> customizer) {
        MfaDslConfigurerImpl<H> mfaDslConfigurer =
                authMethodConfigurerFactory.createMfaConfigurer(this.applicationContext);
        Objects.requireNonNull(customizer, "mfa customizer cannot be null").customize(mfaDslConfigurer);
        AuthenticationFlowConfig mfaFlow = mfaDslConfigurer.build(); 

        platformBuilder.addFlow(mfaFlow);
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