package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.enums.StateType;
import io.contexa.contexaidentity.security.handler.*;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
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
                                               PlatformAuthenticationSuccessHandler  successHandler,
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
            log.trace("AuthenticationFeature [{}]: No relevant AuthenticationStepConfig found in the current flow's steps. Skipping specific configuration for this HttpSecurity instance.", getId());
            return;
        }

        AuthenticationFlowConfig currentFlow = http.getSharedObject(AuthenticationFlowConfig.class);
        log.debug("AuthenticationFeature [{}]: Applying for its relevant step: {} in flow: {}",
                getId(), myRelevantStepConfig.getType(), (currentFlow != null ? currentFlow.getTypeName() : "Single/Unknown"));

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

        // StateConfig 결정
        StateConfig resolvedStateConfig = (stateConfig != null) ? stateConfig :
                (currentFlow != null && currentFlow.getStateConfig() != null) ? currentFlow.getStateConfig() : null;

        // 핸들러 결정 (단일 인증일 때도 StateType에 따라 핸들러 선택)
        PlatformAuthenticationSuccessHandler successHandler = resolveSuccessHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, resolvedStateConfig, appContext);
        PlatformAuthenticationFailureHandler failureHandler = resolveFailureHandler(options, currentFlow, resolvedStateConfig, appContext);

        // 위임 핸들러 설정 (모든 토큰 기반 핸들러)
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
                log.debug("AuthenticationFeature [{}]: Using provided successHandler as OneTimeTokenGenerationSuccessHandler: {}",
                        getId(), successHandler != null ? successHandler.getClass().getName() : "null");

                if (generationSuccessHandler == null) {
                    log.error("AuthenticationFeature [{}]: CRITICAL - determineDefaultOttSuccessHandler returned null. This should not happen. Review BaseOttAuthenticationAdapter.determineDefaultOttSuccessHandler.", getId());
                    throw new IllegalStateException("Unable to determine a valid OneTimeTokenGenerationSuccessHandler for OTT feature " + getId() +
                            ". Resolved successHandler was: " + (successHandler != null ? successHandler.getClass().getName() : "null") +
                            " and determineDefaultOttSuccessHandler also returned null.");
                }
            ottAdapter.configureHttpSecurityForOtt(http, (OttOptions)options, generationSuccessHandler, successHandler, failureHandler);
        } else {
            configureHttpSecurity(http, options, currentFlow, successHandler, failureHandler);
        }

        options.applyCommonSecurityConfigs(http);

        log.info("AuthenticationFeature [{}]: Applied its specific configuration for step type '{}' in flow '{}'.",
                getId(), myRelevantStepConfig.getType(), (currentFlow != null ? currentFlow.getTypeName() : "Single/Unknown"));
    }

    protected PlatformAuthenticationSuccessHandler resolveSuccessHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig, @Nullable List<AuthenticationStepConfig> allSteps,
            @Nullable StateConfig stateConfig,
            ApplicationContext appContext) {

        // StateType 결정 (stateConfig → AuthContextProperties)
        StateType stateType = determineStateType(stateConfig, appContext);
        boolean isMfaFlow = (currentFlow != null && AuthType.MFA.name().equalsIgnoreCase(currentFlow.getTypeName()));

        log.debug("AuthenticationFeature [{}]: Resolving success handler - MFA: {}, StateType: {}",
                getId(), isMfaFlow, stateType);

        if (isMfaFlow) {
            // MFA 인증 핸들러 선택
            if (stateType == StateType.SESSION) {
                log.debug("AuthenticationFeature [{}]: MFA + SESSION mode - using SessionMfaSuccessHandler", getId());
                return appContext.getBean(SessionMfaSuccessHandler.class);
            } else {
                // OAuth2 또는 JWT 모드
                // 1차/2차 구분
                if (allSteps != null) {
                    int currentStepIndex = allSteps.indexOf(myStepConfig);
                    boolean isFirstStepInMfaFlow = (currentStepIndex == 0);

                    if (isFirstStepInMfaFlow) {
                        log.debug("AuthenticationFeature [{}]: MFA primary step with OAuth2/JWT - using PrimaryAuthenticationSuccessHandler", getId());
                        return appContext.getBean(PrimaryAuthenticationSuccessHandler.class);
                    } else {
                        log.debug("AuthenticationFeature [{}]: MFA factor step with OAuth2/JWT - using MfaFactorProcessingSuccessHandler", getId());
                        return appContext.getBean(MfaFactorProcessingSuccessHandler.class);
                    }
                }
                log.warn("AuthenticationFeature [{}]: MFA flow detected but allSteps is null, returning PrimaryAuthenticationSuccessHandler as fallback", getId());
                return appContext.getBean(PrimaryAuthenticationSuccessHandler.class);
            }
        } else {
            // 단일 인증 핸들러 선택
            if (stateType == StateType.SESSION) {
                // SESSION 모드는 Spring Security 기본 핸들러 사용 (null 반환)
                log.debug("AuthenticationFeature [{}]: Single auth + SESSION mode - using Spring Security default handler (null)", getId());
                return null;
            } else {
                // OAuth2 또는 JWT 모드
                log.debug("AuthenticationFeature [{}]: Single auth + OAuth2/JWT mode - using OAuth2SingleAuthSuccessHandler", getId());
                return appContext.getBean(OAuth2SingleAuthSuccessHandler.class);
            }
        }
    }

    protected PlatformAuthenticationFailureHandler resolveFailureHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            @Nullable StateConfig stateConfig,
            ApplicationContext appContext) {

        // StateType 결정
        StateType stateType = determineStateType(stateConfig, appContext);
        boolean isMfaFlow = (currentFlow != null && AuthType.MFA.name().equalsIgnoreCase(currentFlow.getTypeName()));

        log.debug("AuthenticationFeature [{}]: Resolving failure handler - MFA: {}, StateType: {}",
                getId(), isMfaFlow, stateType);

        if (isMfaFlow) {
            // MFA 인증 실패 핸들러 선택
            if (stateType == StateType.SESSION) {
                log.debug("AuthenticationFeature [{}]: MFA + SESSION mode - using SessionMfaFailureHandler", getId());
                return appContext.getBean(SessionMfaFailureHandler.class);
            } else {
                // OAuth2 또는 JWT 모드 - UnifiedAuthenticationFailureHandler 사용
                log.debug("AuthenticationFeature [{}]: MFA + OAuth2/JWT mode - using UnifiedAuthenticationFailureHandler", getId());
                return appContext.getBean(UnifiedAuthenticationFailureHandler.class);
            }
        } else {
            // 단일 인증 실패 핸들러 선택
            if (stateType == StateType.SESSION) {
                // SESSION 모드는 Spring Security 기본 핸들러 사용 (null 반환)
                log.debug("AuthenticationFeature [{}]: Single auth + SESSION mode - using Spring Security default handler (null)", getId());
                return null;
            } else {
                // OAuth2 또는 JWT 모드
                log.debug("AuthenticationFeature [{}]: Single auth + OAuth2/JWT mode - using OAuth2SingleAuthFailureHandler", getId());
                return appContext.getBean(OAuth2SingleAuthFailureHandler.class);
            }
        }
    }

    /**
     * StateType 결정 메서드
     *
     * @param stateConfig StateConfig (nullable)
     * @param appContext ApplicationContext
     * @return StateType
     */
    protected StateType determineStateType(@Nullable StateConfig stateConfig, ApplicationContext appContext) {
        // 1. StateConfig에서 가져오기
        if (stateConfig != null && stateConfig.stateType() != null) {
            return stateConfig.stateType();
        }

        // 2. AuthContextProperties에서 전역 기본값 가져오기
        try {
            AuthContextProperties properties = appContext.getBean(AuthContextProperties.class);
            return properties.getStateType();
        } catch (Exception e) {
            log.warn("Failed to get AuthContextProperties, using JWT as default StateType", e);
            return StateType.JWT;
        }
    }

    /**
     * OTT 기능에 대한 기본 {@link OneTimeTokenGenerationSuccessHandler}를 결정합니다.
     * 이 메서드는 {@link OttAuthenticationAdapter}에서 반드시 재정의되어야 하며,
     * null을 반환해서는 안 됩니다.
     */
    protected OneTimeTokenGenerationSuccessHandler determineDefaultOttGenerationSuccessHandler(ApplicationContext appContext) {
        log.debug("AuthenticationFeature [{}]: Determining default OTT success handler. This should be overridden in OttAuthenticationAdapter.", getId());
        try {
            return appContext.getBean("oneTimeTokenCreationSuccessHandler", OneTimeTokenGenerationSuccessHandler.class);
        } catch (Exception e) {
            String errorMessage = String.format("Default OneTimeTokenGenerationSuccessHandler bean ('oneTimeTokenCreationSuccessHandler' or specific OTT handler) not found for OTT feature: %s. This is a critical configuration error.", getId());
            log.error(errorMessage, e);
            throw new IllegalStateException(errorMessage, e);
        }
    }
}
