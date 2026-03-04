package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexaidentity.security.handler.*;
import io.contexa.contexacommon.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Objects;

@Slf4j
public abstract class AbstractAuthenticationAdapter<O extends AuthenticationProcessingOptions> implements AuthenticationAdapter {

    protected abstract void configureHttpSecurity(HttpSecurity http, O options,
                                                  AuthenticationFlowConfig currentFlow,
                                                  PlatformAuthenticationSuccessHandler successHandler,
                                                  PlatformAuthenticationFailureHandler failureHandler) throws Exception;

    protected void configureHttpSecurityForOtt(HttpSecurity http, OttOptions options,
                                               OneTimeTokenGenerationSuccessHandler ottSuccessHandler,
                                               PlatformAuthenticationSuccessHandler successHandler,
                                               PlatformAuthenticationFailureHandler failureHandler) throws Exception {
        if (!(this instanceof OttAuthenticationAdapter)) {
            throw new UnsupportedOperationException(
                    String.format("Feature %s is not an OTT feature and should not call configureHttpSecurityForOtt. " +
                            "This method must be overridden by OttAuthenticationAdapter.", getId())
            );
        }
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> allStepsInCurrentFlow, StateConfig stateConfig) throws Exception {
        Objects.requireNonNull(http, "HttpSecurity cannot be null");

        AuthenticationStepConfig myRelevantStepConfig = null;
        if (!CollectionUtils.isEmpty(allStepsInCurrentFlow)) {
            for (AuthenticationStepConfig step : allStepsInCurrentFlow) {
                if (getId().equalsIgnoreCase(step.getType())) {
                    myRelevantStepConfig = step;
                    break;
                }
            }
        }

        if (myRelevantStepConfig == null) {
            return;
        }
        AuthenticationFlowConfig currentFlow = http.getSharedObject(AuthenticationFlowConfig.class);
        O options = (O) myRelevantStepConfig.getOptions().get("_options");
        if (options == null) {
            throw new IllegalStateException(
                    String.format("AuthenticationFeature [%s]: Options not found in AuthenticationStepConfig for type '%s'. " +
                            "Ensure XxxDslConfigurerImpl correctly builds and stores options.", getId(), myRelevantStepConfig.getType())
            );
        }

        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        Assert.state(platformContext != null, "PlatformContext not found in HttpSecurity shared objects. It must be set by the orchestrator.");
        ApplicationContext appContext = platformContext.applicationContext();
        Objects.requireNonNull(appContext, "ApplicationContext from PlatformContext cannot be null");

        StateConfig resolvedStateConfig = (stateConfig != null) ? stateConfig :
                (currentFlow != null && currentFlow.getStateConfig() != null) ? currentFlow.getStateConfig() : null;

        StateType stateType = determineStateType(resolvedStateConfig, appContext);

        SecurityContextRepository securityContextRepository = resolveSecurityContextRepository(
                stateType, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, options
        );

        if (stateType == StateType.SESSION
                && http.getSharedObject(SecurityContextRepository.class) instanceof AISessionSecurityContextRepository) {
            // Session mode: keep AISessionSecurityContextRepository from global registration
        } else if (stateType != StateType.SESSION) {
            // OAuth2/Stateless: force NullSecurityContextRepository, Zero Trust handled by AIOAuth2ZeroTrustFilter
            http.setSharedObject(SecurityContextRepository.class, new NullSecurityContextRepository());
        } else if (!(securityContextRepository instanceof NullSecurityContextRepository)) {
            http.setSharedObject(SecurityContextRepository.class, securityContextRepository);
        }

        PlatformAuthenticationSuccessHandler successHandler = resolveSuccessHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, resolvedStateConfig, appContext);
        PlatformAuthenticationFailureHandler failureHandler = resolveFailureHandler(options, currentFlow, resolvedStateConfig, appContext);

        if (successHandler instanceof AbstractTokenBasedSuccessHandler tokenBasedSuccessHandler) {
            if (options.getSuccessHandler() != null) {
                tokenBasedSuccessHandler.setDelegateHandler(options.getSuccessHandler());
            }
        }

        if (failureHandler instanceof AbstractTokenBasedFailureHandler tokenBasedFailureHandler) {
            if (options.getFailureHandler() != null) {
                tokenBasedFailureHandler.setDelegateHandler(options.getFailureHandler());
            }
        }

        OneTimeTokenGenerationSuccessHandler generationSuccessHandler;

        if (this instanceof BaseOttAuthenticationAdapter ottAdapter) {
            generationSuccessHandler = determineDefaultOttGenerationSuccessHandler(appContext);

            if (generationSuccessHandler == null) {
                log.error("AuthenticationFeature [{}]: CRITICAL - determineDefaultOttSuccessHandler returned null. This should not happen. Review BaseOttAuthenticationAdapter.determineDefaultOttSuccessHandler.", getId());
                throw new IllegalStateException("Unable to determine a valid OneTimeTokenGenerationSuccessHandler for OTT feature " + getId() +
                        ". Resolved successHandler was: " + (successHandler != null ? successHandler.getClass().getName() : "null") +
                        " and determineDefaultOttSuccessHandler also returned null.");
            }
            ottAdapter.configureHttpSecurityForOtt(http, (OttOptions) options, generationSuccessHandler, successHandler, failureHandler);
        } else {
            configureHttpSecurity(http, options, currentFlow, successHandler, failureHandler);
        }
        options.applyCommonSecurityConfigs(http);

    }

    protected PlatformAuthenticationSuccessHandler resolveSuccessHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig, @Nullable List<AuthenticationStepConfig> allSteps,
            @Nullable StateConfig stateConfig,
            ApplicationContext appContext) {

        StateType stateType = determineStateType(stateConfig, appContext);
        boolean isMfaFlow = (currentFlow != null && AuthType.MFA.name().equalsIgnoreCase(currentFlow.getTypeName()));

        if (isMfaFlow) {
            if (allSteps != null) {
                int currentStepIndex = allSteps.indexOf(myStepConfig);
                boolean isFirstStepInMfaFlow = (currentStepIndex == 0);

                if (isFirstStepInMfaFlow) {
                    return appContext.getBean(PrimaryAuthenticationSuccessHandler.class);
                } else {
                    return appContext.getBean(MfaFactorProcessingSuccessHandler.class);
                }
            }
            log.error("AuthenticationFeature [{}]: MFA flow detected but allSteps is null, returning PrimaryAuthenticationSuccessHandler as fallback", getId());
            return appContext.getBean(PrimaryAuthenticationSuccessHandler.class);
        } else {
            if (stateType == StateType.SESSION) {
                return null;
            } else {
                return appContext.getBean(OAuth2SingleAuthSuccessHandler.class);
            }
        }
    }

    protected PlatformAuthenticationFailureHandler resolveFailureHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            @Nullable StateConfig stateConfig,
            ApplicationContext appContext) {

        StateType stateType = determineStateType(stateConfig, appContext);
        boolean isMfaFlow = (currentFlow != null && AuthType.MFA.name().equalsIgnoreCase(currentFlow.getTypeName()));

        if (isMfaFlow) {

            return appContext.getBean(UnifiedAuthenticationFailureHandler.class);
        } else {

            if (stateType == StateType.SESSION) {

                return null;
            } else {

                return appContext.getBean(OAuth2SingleAuthFailureHandler.class);
            }
        }
    }

    protected StateType determineStateType(@Nullable StateConfig stateConfig, ApplicationContext appContext) {

        if (stateConfig != null && stateConfig.stateType() != null) {
            return stateConfig.stateType();
        }

        try {
            AuthContextProperties properties = appContext.getBean(AuthContextProperties.class);
            return properties.getStateType();
        } catch (Exception e) {
            log.error("Failed to get AuthContextProperties, using JWT as default StateType", e);
            return StateType.OAUTH2;
        }
    }

    protected SecurityContextRepository resolveSecurityContextRepository(
            StateType stateType,
            @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig,
            @Nullable List<AuthenticationStepConfig> allSteps, O options) {

        boolean isMfaFlow = (currentFlow != null && AuthType.MFA.name().equalsIgnoreCase(currentFlow.getTypeName()));

        if (isMfaFlow) {
            if (allSteps != null) {
                int currentStepIndex = allSteps.indexOf(myStepConfig);
                boolean isFirstStepInMfaFlow = (currentStepIndex == 0);
                boolean isFinalStepInMfaFlow = (currentStepIndex == allSteps.size() - 1);

                if (isFirstStepInMfaFlow && !isFinalStepInMfaFlow) {
                    if(options.getSecurityContextRepository() != null) {
                        return options.getSecurityContextRepository();
                    }
                    return new NullSecurityContextRepository();

                } else if (isFinalStepInMfaFlow) {
                    return getSecurityContextRepository(stateType, options);
                } else {
                    return new NullSecurityContextRepository();
                }
            }

            log.error("AuthenticationFeature [{}]: MFA flow detected but allSteps is null, using NullSecurityContextRepository as fallback", getId());
            return new NullSecurityContextRepository();
        } else {
            return getSecurityContextRepository(stateType, options);
        }
    }

    private static <O extends AuthenticationProcessingOptions> @NonNull SecurityContextRepository getSecurityContextRepository(StateType stateType, O options) {
        if(options.getSecurityContextRepository() != null) {
            return options.getSecurityContextRepository();
        }
        if (stateType == StateType.SESSION) {
            return new HttpSessionSecurityContextRepository();
        } else {
            return new NullSecurityContextRepository();
        }
    }

    protected OneTimeTokenGenerationSuccessHandler determineDefaultOttGenerationSuccessHandler(ApplicationContext appContext) {
        try {
            return appContext.getBean("oneTimeTokenCreationSuccessHandler", OneTimeTokenGenerationSuccessHandler.class);
        } catch (Exception e) {
            String errorMessage = String.format("Default OneTimeTokenGenerationSuccessHandler bean ('oneTimeTokenCreationSuccessHandler' or specific OTT handler) not found for OTT feature: %s. This is a critical configuration error.", getId());
            log.error(errorMessage, e);
            throw new IllegalStateException(errorMessage, e);
        }
    }
}
